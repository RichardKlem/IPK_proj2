//
// Created by Richard Klem on 24.04.20.
//
#include <string>
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

    std::stringstream ss(str);

    if((ss >> num).fail())
        return result;
    result = {S2I_OK, num};
    return result;
}