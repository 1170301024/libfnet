#include    <stdlib.h>
#include    <string.h>

/*
 * convert a string to a signed integer
 * We are supposed to use the function instead of atoi because function atoi
 * cannot handle the string "0".
 * 
 * the function return -1 for the strings like "00", "0...0" 
 * \return 0 for sucess, -1 for fail
 */
int 
fnet_atoi(int * ret_val, const char *s){
    
    if(s == NULL){
        return -1;
    }

    int r;

    if((r = atoi(s)) != 0){
        *ret_val = r;
        return 0;
    }
    else if(*s == '0'){
        *ret_val = 0;
        return 0;
    }
    return -1;
}