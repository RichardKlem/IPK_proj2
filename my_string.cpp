//
// Created by Richard Klem on 24.04.20.
//
#include <cstring>
#include <sstream>
#include "my_string.h"

/**
 * Převede řetězec na číslo
 * @param str vstupní řetězec
 * @return int výstupní struktura obsahující dvojici (status, číslo)
 */
str2int_struct_t str2int (char * str){
    str2int_struct_t result {S2I_FAIL, 0};
    int num;

    if (str == nullptr)
        return result;

    // ošetření, že se nevyskytuje žádný NEnumerický znak
    for (unsigned int i = 0; i < strlen(str); ++i) {
        if (!isdigit(str[i]))
            return result;
    }

    long int tmp = strtol(str, nullptr, 0);
    if (tmp > 65535)  //port je velikosti unsigned int tedy čísla 0 - 65565
        return result;
    num = (int) tmp;

    result = {S2I_OK, num};
    return result;
}