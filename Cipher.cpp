//  Cipher.cpp
//  AES

#include "Cipher.hpp"

Cipher::Cipher(){}

/*
 Shift the columns within the State's row by the row number
 Lowest positions in the row are swaped into highest positions,
 while highest positions change to lower positions
 **/
void Cipher::shiftRows(unsigned char** st){
    int row = 1;
    shiftColumnsByOne(st, &row, true);
    shiftColumnsByTwo(st, &(++row));
    shiftColumnsByOne(st, &(++row), false);   //Shift to the left by 1 is equivalent to shift to the right by 3
}
/**
 Shift Columns in a State by one to either the left or right direction
 @param st - 2D State array that will be modified
 @param row - row within the State that will be modified
 @param rightDir - if true shift in right direction, else in left direction
 */
void Cipher::shiftColumnsByOne(unsigned char** st, int* row, bool rightDir){
    if(rightDir){
        for(int column = 0; column < 3; column++){
            unsigned char temp = st[*row][column];
            int next = (column + 1) % 4;
            st[*row][column] = st[*row][next];
            st[*row][next] = temp;
        }
    }else{
        for(int column = 3; column > 0; column--){
            unsigned char temp = st[*row][column];
            int next = (column + 1) % 4;
            st[*row][column] = st[*row][next];
            st[*row][next] = temp;
        }
    }
}

/**
 Shift Columns in a State by two, so that
    st[0] = st[2]
    st[1] = st[3]
 @param st - 2D 4x4 State array that will be modified
 @param row - row within the State that will be modified
 */
void Cipher::shiftColumnsByTwo(unsigned char** st, int* row){
    for(int column = 0; column < 2; column++){
        unsigned char temp = st[*row][column];
        st[*row][column] = st[*row][column+2];
        st[*row][column+2] = temp;
    }
}
