
#include "sgx_crypto.h"


sgx_enclave_id_t SGX_Crypto::initEnclave()
{/*Enclave Initialization*/
	sgx_enclave_id_t eid;//Enclave ID
	sgx_status_t ret = SGX_SUCCESS; // For Checking if enclave was created successfully
	int updated = 0;
	sgx_launch_token_t token = { 0 };

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("\nEnclave Cannot be initialized\n");
		return { 0 };
	}
	return eid;
}


size_t SGX_Crypto::getLen(size_t textLength)
{
	return textLength + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;// ������������ ������ ������, ��� ��������� ������, ����� �� ���� �������������� ������. ����������� ����� ������ ����� ����� ������������ ������ MAC+ IV
}

size_t SGX_Crypto::getEncrypt(char* plainText, size_t plainTextLength, sgx_sealed_data_t* outSealBuffer, char* outTextBuffer) // �-� ���������� ��� GUI, �� GUI ���...(���������� ������ ��� ����������)
{
	/*��������*/
	errno_t err = 0;

	/*���������� �������*/
	char debug[15] = "SUCCESS";
	uint8_t debugSize = 15;

	/*������������� �������*/
	auto eid = initEnclave();

	/*���������� ������ � ������������� �������*/
	uint32_t sealedDataSize = 0;
	sizeOfSealData(eid, &sealedDataSize);
	sgx_sealed_data_t* sealedData = (sgx_sealed_data_t*)malloc((sealedDataSize) * (sizeof(sgx_sealed_data_t)));//��������� ����� ��� ������������ ������

	/*������������� ����� �������������� ������*/
	size_t encTextLength = getLen(plainTextLength);
	char* encText = (char*)malloc((encTextLength) * (sizeof(char)));
	//char* recovered = new char[plainTextLength];

	/*��������� ������������� ����� ��� �������� ��������*/
	seal(eid, (sgx_sealed_data_t*)sealedData, sealedDataSize, debug, debugSize);
	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_enc_mem;
	}


	/*���������� ������*/
	encryptText(eid, plainText, plainTextLength, encText, encTextLength, (sgx_sealed_data_t*)sealedData, sealedDataSize, debug, debugSize);//����� ������� ���������� �� �������


	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_enc_mem;
	}
	//Encryption Successful;



	/*Debug Stuff*/

	/*decryptText(eid, cipherText, ciphertext_len, recovered, plaintext_len, (sgx_sealed_data_t *)sealed_data, sealed_data_size, debug, debug_size);
	recovered[plaintext_len] = '\0';
	printf("\nrecovered\n");
	printf(recovered);*/

	/*�������� �������*/
	if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
		printf("Enclave is not securely detroyed");
	}

	//�������� ������
	memcpy(outSealBuffer, sealedData, sealedDataSize);
	memcpy(outTextBuffer, encText, encTextLength);

	/*������������ ������*/
free_enc_mem:
	free(sealedData);
	free(encText);

	/*��� ������. ����� ������*/

	return encTextLength;
}



size_t SGX_Crypto::getDecrypt(char* encText, size_t encTextLength, sgx_sealed_data_t* sealData, char* outTextBuffer)
{	/*Delarations*/
	errno_t err = 0;


	/*Debug Variables*/
	char debug[15] = "SUCCESS";
	uint8_t debugSize = 15;

	/*Enclave Initialization*/
	auto eid = initEnclave();

	/*������������� ������ ������������ ������*/
	uint32_t sealedDataSize = 0;
	sizeOfSealData(eid, &sealedDataSize);
	sgx_sealed_data_t* sealedData = (sgx_sealed_data_t*)malloc((sealedDataSize) * (sizeof(sgx_sealed_data_t)));

	memcpy(sealedData, sealData, sealedDataSize);

	/*������������� ������ �������� �������*/
	size_t decTextLength = encTextLength - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE ; //Space allocation
	char* decText = (char*)malloc((decTextLength) * (sizeof(char)));

	/*����������� �������������� ������*/
	decryptText(eid, encText, encTextLength, decText, decTextLength, (sgx_sealed_data_t*)sealedData, sealedDataSize, debug, debugSize);
	

	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_memory_dnc;
	}
	


	/*�������� �������*/
	if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
		printf("Enclave is not securely detroyed");
	}

	//�������� ������
	memcpy(outTextBuffer, decText, decTextLength);
	outTextBuffer[decTextLength] = '\0';

	/*������� ������*/
free_memory_dnc:
	free(sealedData);
	free(decText);

	return decTextLength;
}


