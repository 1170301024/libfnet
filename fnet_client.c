
#include "include/libfnet.h"


static int usage (char *s){
    printf("usage: %s <command> [OPTIONS] file1 [file2 ...]\n", s);
    
    printf("\nThese are common fnet commands\n"
           "   connect              Connect to the  server\n"
           "   config               Configure the required feature set to the server\n"
           "   start                Start distributing the features of traffic flow\n"
           "   pause                Pause distributing features of traffic flow\n"
           "   restore              Restore distrubution service\n");
    printf("\nwhere OPTIONS are as follows:\n");
    printf("\nGeneral options\n"
           "   output=F             write output the file F(otherwise stdout is used)\n"
           "   config=F             read feature configuration from file(F)");
    printf("\nData feature options\n"
           "   ip=1                 include ip feature information\n"
           "   tcp=1                include tcp feature information\n"
           "   ppi=1                include per packet information feature"
           "   fingerprints=1       include fingerprints feature"
           "   wht=1                include WHT protocol feature"
           "   dns=1                include DNS protocol feature"
           "   ssh=1                include SSH protocol feature"
           "   tls=1                include TLS protocol feature"
           "   dhcp=1               include DHCP protocol feature"
           "   dhcpv6=1             include DHCPv6 protocol feature"
           "   http=1               include HTTP protocol feature"
           "   ike=1                include Internel Key Exchange protocol feature"
           "   payload=1            include payload for each flow"
           "   exe=1                include information about host process associated with flow"
           "   idp=N                report N bytes of the initial data packet of each flow\n"
           "   debug=1              include debug information\n"
           "   expire_type=1        include expire_type feature");
    printf("RETURN VALUE                 0 if no errors; nonzero otherwise\n");
    return 0;
}

int main(void){
    
}

