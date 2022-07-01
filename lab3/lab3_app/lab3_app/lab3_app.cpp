#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <string.h>

#include "sgx_urts.h" //базовый заголовок, в котором упакованы функции создания и удаления анклава и многие другие
#include "sgx_tseal.h"
#include "lab3_enc_u.h" //подключение автоматически сгенерированного файла

#define ENCLAVE_FILE _T("lab3_enc.signed.dll") //библиотека, через которую осуществляется подпись анклава	

#define BUF_LEN 100



int main()
{
    char buffer[BUF_LEN] = { 0 }; //создаем пустую переменную, в которую запишем секрет из анклава

    sgx_enclave_id_t eid; // id анклава, в проекте может быть несколько анклавов, каждый со своим id
    sgx_status_t ret = SGX_SUCCESS; //необходимо для отлавливания ошибок на этапе доступа к анклаву	 
    sgx_launch_token_t token = { 0 }; //инициализация токена запуска для анклава
    int updated = 0; // токен запуска не был изменен

    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL); //функция создания анклава
    if (ret != SGX_SUCCESS) {
        printf("App: error %#x, failed to create enclave. \n", ret);
        return -1;
    }

    while (true)
    {
        printf("Input index to retrieve, or -1 to exit: \t");
        int idx = -1;
        scanf_s("%d", &idx); 
        if (idx < 0) {
            return 0;
        }
        foo(eid, buffer, BUF_LEN, idx); 
        printf("%s\n=======================\n\n", buffer);
       // std::cout << buffer<<"\n";
    }
    if (SGX_SUCCESS != sgx_destroy_enclave(eid))
        return -1;
    return 0;
}
