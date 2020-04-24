//
// Created by richardklem on 24.04.20.
//

#ifndef PROJ2_MY_STRING_H
#define PROJ2_MY_STRING_H
enum STR2INT_STATUS_CODE {S2I_FAIL, S2I_OK};
struct str2int_struct_t{
    STR2INT_STATUS_CODE status;
    int num;
};
str2int_struct_t str2int(char * str);
#endif //PROJ2_MY_STRING_H
