/*
* Copyright 2011 Kestrel Signal Processing, Inc.
* Copyright 2011, 2014 Range Networks, Inc.
*
* This software is distributed under the terms of the GNU Affero Public License.
* See the COPYING file in the main directory for details.
*
* This use of this software may be subject to additional restrictions.
* See the LEGAL file in the main directory for details.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <arpa/inet.h>
#include <cstdlib>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <osip2/osip.h>
#include <osipparser2/osip_message.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Adding in some libraries */
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <Globals.h>
#include "servershare.h"
#include "SubscriberRegistry.h"

using namespace std;

//ConfigurationTable gConfig("/etc/OpenBTS/sipauthserve.db", "sipauthserve", getConfigurationKeys());

int my_udp_port;

// just using this for the database access
SubscriberRegistry gSubscriberRegistry;

void prettyPrint(const char *label, osip_message_t *sip)
{
    char *dest=NULL;
    size_t length=0;
    int i = osip_message_to_str(sip, &dest, &length);
    if (i!=0) {
        spdlog::error("cannot get printable message");
    } else {
        spdlog::info("{}: {}", label, dest);
        osip_free(dest);
    }
}

string imsiFromSip(osip_message_t *sip)
{
    char *dest;
    osip_uri_t *fromUri = osip_from_get_url(sip->from);
    if (!fromUri) {
        //(ERR) << "osip_from_get_url problem";
        spdlog::error("osip_from_get_url problem");
        return "";
    }
    osip_uri_to_str(fromUri, &dest);
    string imsi = dest;
    osip_free(dest);
    return imsi;
}

string imsiToSip(osip_message_t *sip)
{
    char *dest;
    osip_uri_t *toUri = osip_to_get_url(sip->to);
    if (!toUri) {
        spdlog::error("osip_to_get_url problem");
        return "";
    }
    osip_uri_to_str(toUri, &dest);
    string imsi = dest;
    osip_free(dest);
    return imsi;
}

// is imsi in the database?
bool imsiFound(string imsi)
{
    string x = gSubscriberRegistry.imsiGet(imsi, "id");
    return x.length() != 0;
}

string imsiClean(string imsi)
{
    // remove leading sip:
    if (0 == strncasecmp(imsi.c_str(), "sip:", 4)) {
        imsi = imsi.substr(4);
    }
    // remove trailing @...
    size_t p = imsi.find("@");
    if (p != string::npos) {
        imsi = imsi.substr(0, p);
    }
    // remove leading IMSI
    if (0 == strncasecmp(imsi.c_str(), "imsi", 4)) {
        imsi = imsi.substr(4);
    }
    return imsi;
}

#define CONFIG_IGNORE_AUTHENTICATION false

char *processBuffer(char *buffer)
{
    int i;

    // parse sip message
    osip_message_t *sip;
    i=osip_message_init(&sip);
    if (i!=0) {
        spdlog::error("cannot allocate");
        osip_message_free(sip);
        return NULL;
    }
    i=osip_message_parse(sip, buffer, strlen(buffer));
    if (i!=0) {
        spdlog::error("cannot parse sip message");
        osip_message_free(sip);
        return NULL;
    }

    prettyPrint("request", sip);

    // response starts as clone of message
    osip_message_t *response;
    osip_message_clone(sip, &response);

    osip_from_t * contact_header = (osip_from_t*)osip_list_get(&sip->contacts,0);
    osip_uri_t* contact_url = contact_header->url; 
    char *remote_host = contact_url->host;
    char *remote_port = contact_url->port;

    // return via
    ostringstream newvia;
    // newvia << "SIP/2.0/UDP localhost:5063;branch=1;received=string_address@foo.bar";
    const char *my_ipaddress = "localhost";
    newvia << "SIP/2.0/UDP " << my_ipaddress << ":" << my_udp_port << ";branch=1;received="
        << "string_address@foo.bar"; // << my_network.string_addr((struct sockaddr *)netaddr, netaddrlen, false);
    osip_message_append_via(response, newvia.str().c_str());

    // no method
    osip_message_set_method(response, NULL);

    string imsi = imsiClean(imsiFromSip(sip));
    string imsiTo = imsiClean(imsiToSip(sip));
    if ((imsi == "EXIT") && (imsiTo == "EXIT")) exit(0); // for testing only
    if (!imsiFound(imsi)) {
        spdlog::warn("imsi unknown");
        // imsi problem => 404 IMSI Not Found
        osip_message_set_status_code (response, 404);
        osip_message_set_reason_phrase (response, osip_strdup("IMSI Not Found"));
    } else if (CONFIG_IGNORE_AUTHENTICATION) {
                osip_message_set_status_code (response, 200);
                osip_message_set_reason_phrase (response, osip_strdup("OK"));
                spdlog::info("success, imsi {} registering for IP address {}", imsi, remote_host);
                gSubscriberRegistry.imsiSet(imsi,"ipaddr", remote_host, "port", remote_port);
    } else {
        // look for rand and sres in Authorization header (assume imsi same as in from)
        string randx;
        string sres;
        // sip parser is not working reliably for Authorization, so we'll do the parsing
        char *RAND = strcasestr(buffer, "nonce=");
        char *SRES = strcasestr(buffer, "response=");
        if (RAND && SRES) {
            // find RAND digits
            RAND += 6;
            while (!isalnum(*RAND)) { RAND++; }
            RAND[32] = 0;
            int j=0;
            // FIXME -- These loops should use strspn instead.
            while(isalnum(RAND[j])) { j++; }
            RAND[j] = '\0';
            // find SRES digits
            SRES += 9;
            while (!isalnum(*SRES)) { SRES++; }
            int i=0;
            // FIXME -- These loops should use strspn instead.
            while(isalnum(SRES[i])) { i++; }
            SRES[i] = '\0';
            spdlog::info("rand = /{}/", RAND);
            spdlog::info("sres = /{}/", SRES);
        }
        if (!RAND || !SRES) {
            spdlog::warn("imsi {} known, 1st register", imsi);
            // no rand and sres => 401 Unauthorized
            osip_message_set_status_code (response, 401);
            osip_message_set_reason_phrase (response, osip_strdup("Unauthorized"));
            // but include rand in www_authenticate
            osip_www_authenticate_t *auth;
            osip_www_authenticate_init(&auth);
            // auth type is required by osip_www_authenticate_to_str (and therefore osip_message_to_str)
            string auth_type = "Digest";
            osip_www_authenticate_set_auth_type(auth, osip_strdup(auth_type.c_str()));
            // returning RAND in www_authenticate header
            string randz = generateRand(imsi);
            osip_www_authenticate_set_nonce(auth, osip_strdup(randz.c_str()));
            i = osip_list_add (&response->www_authenticates, auth, -1);
            if (i < 0) {
                spdlog::error("problem adding www_authenticate");
            }
        } else {
            string kc;
            bool sres_good = authenticate(imsi, RAND, SRES, &kc);
            spdlog::info("imsi {} known, 2nd register, good = {}", imsi, sres_good);
            if (sres_good) {
                // sres matches rand => 200 OK
                osip_message_set_status_code (response, 200);
                osip_message_set_reason_phrase (response, osip_strdup("OK"));
                if (kc.size() != 0) {
                    osip_authentication_info *auth;
                    osip_authentication_info_init(&auth);
                    osip_authentication_info_set_cnonce(auth, osip_strdup(kc.c_str()));
                    i = osip_list_add (&response->authentication_infos, auth, -1);
                    if (i < 0) {
                        spdlog::error("problem adding authentication_infos");
                    }
                }
                // (pat 9-2013) Add the caller id.
                static string calleridstr("callerid");
                string callid = gSubscriberRegistry.imsiGet(imsi,calleridstr);
                if (callid.size()) {
                    char buf[120];
                    // Per RFC3966 the telephone numbers should begin with "+" only if it is globally unique throughout the world.
                    // We should not add the "+" here, it should be in the database if appropriate.
                    snprintf(buf,120,"<tel:%s>",callid.c_str());
                    osip_message_set_header(response,"P-Associated-URI",buf);
                }
                // And register it.
                spdlog::info("success, registering for IP address {}", remote_host);
                gSubscriberRegistry.imsiSet(imsi,"ipaddr", remote_host, "port", remote_port);
            } else {
                // sres does not match rand => 401 Unauthorized
                osip_message_set_status_code (response, 401);
                osip_message_set_reason_phrase (response, osip_strdup("Unauthorized"));
            }
        }
    }

    prettyPrint("response", response);
    size_t length = 0;
    char *dest;
    int ii = osip_message_to_str(response, &dest, &length);
    if (ii != 0) {
        spdlog::error("cannot get printable message");
    }

    osip_message_free(sip);
    osip_message_free(response);

    return dest;
}


#define BUFLEN 5000
#define CONFIG_PORT 5064

int
main(int argc, char **argv)
{
    /*** Setup Logger ***/
    // create color multi threaded logger
    auto console_logger = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(console_logger);

    // TODO: Properly parse and handle any arguments
    if (argc > 1) {
        for (int argi = 0; argi < argc; argi++) {
            if (!strcmp(argv[argi], "--version") ||
                !strcmp(argv[argi], "-v")) {
                cout << gVersionString << endl;
            }
        }

        return 0;
    }

    sockaddr_in si_me;
    sockaddr_in si_other;
    int aSocket;
    char buf[BUFLEN];

    spdlog::warn("SipAuthServe Starting");

    srand ( time(NULL) + (int)getpid() );
    my_udp_port = CONFIG_PORT; // This should come from a config file
    gSubscriberRegistry.init();
    spdlog::info("SubscriberRegistry initialized");

    // init osip lib
    osip_t *osip;
    int i=osip_init(&osip);
    if (i!=0) {
        spdlog::critical("cannot init sip lib");
        exit(1);
    }

    if ((aSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        spdlog::critical("can't initialize socket");
        exit(1);
    }

    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(my_udp_port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(aSocket, (sockaddr*)&si_me, sizeof(si_me)) == -1) {
        spdlog::critical("can't bind socket on port {}", my_udp_port);
        exit(1);
    }

    spdlog::warn("Binding on port {}", my_udp_port);

    while (true) {
        //gConfig.purge();
        socklen_t slen = sizeof(si_other);
        memset(buf, 0, BUFLEN);
        if (recvfrom(aSocket, buf, BUFLEN, 0, (sockaddr*)&si_other, &slen) == -1) {
            spdlog::error("recvfrom problem");
            continue;
        }

        spdlog::info("receiving: {}", buf);

        char *dest = processBuffer(buf);
        if (dest == NULL) {
            continue;
        }

        if (sendto(aSocket, dest, strlen(dest), 0, (sockaddr*)&si_other, sizeof(si_other)) == -1) {
            spdlog::error("sendto problem");
            continue;
        }
        osip_free(dest);
    }

    close(aSocket);
    return 0;
}
