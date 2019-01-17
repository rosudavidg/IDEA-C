#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>

#define KEY  "00000000011001000000000011001000000000010010110000000001100100000000000111110100000000100101100000000010101111000000001100100000"
#define DATA "0000010100110010000010100110010000010100110010000001100111111010"

#define KEY_SIZE         128
#define DATA_SIZE        64
#define SUBKEY_SIZE      16
#define SUBKEYS_NO       52
#define SHIFT_KEY_OFFSET 25
#define NO_ROUNDS        8

// Alocare memorie pentru variabile
void alloc_memory(char** key, char** data, char** encrypted_data, char*** subkeys) {
	(*key)            = (char*) malloc(sizeof(char) * KEY_SIZE);
	(*data)           = (char*) malloc(sizeof(char) * DATA_SIZE);
	(*encrypted_data) = (char*) malloc(sizeof(char) * DATA_SIZE);

	(*subkeys) = (char**) malloc(sizeof(char*) * SUBKEYS_NO);
	for (int i = 0; i < SUBKEYS_NO; i++) {
		(*subkeys)[i] = (char*) malloc(sizeof(char) * SUBKEY_SIZE);
	}
}

// Eliberare memorie pentru variabile
void free_memory(char** key, char** data, char** encrypted_data, char*** subkeys) {
	free(*key);
	free(*data);
	free(*encrypted_data);

	for (int i = 0; i < SUBKEYS_NO; i++) {
		free((*subkeys)[i]);
	}
	free((*subkeys));
}

// Seteaza valorile pentru key si pentru data
void set_values(char** key, char** data) {
	for (int i = 0; i < KEY_SIZE; i++) {
		(*key)[i] = KEY[i];
	}

	for (int i = 0; i < DATA_SIZE; i++) {
		(*data)[i] = DATA[i];
	}
}

// Afisarea datelor criptate
void print_encrypted_data(char* encrypted_data) {
	for (int i = 0; i < DATA_SIZE; i++) {
		printf("%c", encrypted_data[i]);
	}
	printf("\n");
}

// Shifteaza cheia prin rotatie cu SHIFT_KEY_OFFSET bits la stanga
void shift_key(char** key) {
	char* tmp = (char*) malloc(sizeof(char) * SHIFT_KEY_OFFSET);

	// Copierea primilor SHIFT_KEY_OFFSET bits
	for (int i = 0; i < SHIFT_KEY_OFFSET; i++) {
		tmp[i] = (*key)[i];
	}

	// Shiftarea celor KEY_SIZE - SHIFT_KEY_OFFSET bits la stanga
	for (int i = 0; i < KEY_SIZE - SHIFT_KEY_OFFSET; i++) {
		(*key)[i] = (*key)[i + SHIFT_KEY_OFFSET];
	}

	// Copierea celor SHIFT_KEY_OFFSET bits la capatul cheii
	for (int i = 0; i < SHIFT_KEY_OFFSET; i++) {
		(*key)[i + KEY_SIZE - SHIFT_KEY_OFFSET] = tmp[i];
	}

	free(tmp);
}

// Calculeaza subcheile necesare
void compute_subkeys(char* key, char*** subkeys) {
	int index = 0;

	for (int i = 0; i < SUBKEYS_NO; i++) {
		if (index == KEY_SIZE / SUBKEY_SIZE) {
			shift_key(&key);
			index = 0;
		}

		for (int j = 0; j < SUBKEY_SIZE; j++) {
			(*subkeys)[i][j] = key[index * SUBKEY_SIZE + j];
		}

		index++;
	}
}

// Convertirea intrarii in format uint16_t (partea index din data)
uint16_t to_uint16_t(char* data, int index) {
	uint16_t result = 0;
	for (int i = 0; i < SUBKEY_SIZE; i++) {
		result <<= 1;
		result += data[index * SUBKEY_SIZE + i] == '0'? 0 : 1;
	}

	return result;	
}

// Convertirea subcheilor din char in uint16_t
void subkeys_to_uint16_t(char** subkeys, uint16_t** subkeys_16_t) {
	for (int i = 0; i < SUBKEYS_NO; i++) {
		(*subkeys_16_t)[i] = 0;
		
		for (int j = 0; j < SUBKEY_SIZE; j++) {
			(*subkeys_16_t)[i] <<= 1;
			(*subkeys_16_t)[i] += subkeys[i][j] == '0'? 0 : 1;
		}
	}
}

// Inmultirea a doua valori uint16_t
uint16_t multiply(uint16_t a, uint16_t b) {
	uint32_t c = a * b;

	if (c == 0) {
		return (1 + (-1) * a + (-1) * b) & 0xFFFF;
	} else {
		uint16_t high = (c >> 16) & 0xFFFF;
		uint16_t low  = c & 0xFFFF;

		if (low > high) {
			c = low - high;
		} else {
			c = (low - high) + 1;
		}
		return c & 0xFFFF;
	}
}

// Calculeaza cheia in functie de ultimele calcule
void set_encrypted_data(char** encrypt_data, uint16_t c1, uint16_t c2, uint16_t c3, uint16_t c4) {
	for (int i = SUBKEY_SIZE - 1; i >= 0; i--) {
		if (((c1 >> i) & 0x1) == 1) {
			(*encrypt_data)[SUBKEY_SIZE * 0 + SUBKEY_SIZE - i - 1] = '1';
		}
	}

	for (int i = SUBKEY_SIZE - 1; i >= 0; i--) {
		if (((c2 >> i) & 0x1) == 1) {
			(*encrypt_data)[SUBKEY_SIZE * 1 + SUBKEY_SIZE - i - 1] = '1';
		}
	}
	
	for (int i = SUBKEY_SIZE - 1; i >= 0; i--) {
		if (((c3 >> i) & 0x1) == 1) {
			(*encrypt_data)[SUBKEY_SIZE * 2 + SUBKEY_SIZE - i - 1] = '1';
		}
	}
	
	for (int i = SUBKEY_SIZE - 1; i >= 0; i--) {
		if (((c4 >> i) & 0x1) == 1) {
			(*encrypt_data)[SUBKEY_SIZE * 3 + SUBKEY_SIZE - i - 1] = '1';
		}
	}
}

// Functia de criptare
void encrypt_data(char* data, char** encrypted_data, uint16_t* subkeys) {
	for (int i = 0; i < DATA_SIZE; i++) {
		(*encrypted_data)[i] = '0';
	}

	uint16_t X0, X1, X2, X3;

	X0 = to_uint16_t(data, 0);
	X1 = to_uint16_t(data, 1);
	X2 = to_uint16_t(data, 2);
	X3 = to_uint16_t(data, 3);

	for (int i = 0; i < 8; i++) {
		uint16_t c1 = multiply(X0, subkeys[i * 6 + 0]);
		uint16_t c2 = X1 + subkeys[i * 6 + 1];
		uint16_t c3 = X2 + subkeys[i * 6 + 2];
		uint16_t c4 = multiply(X3, subkeys[i * 6 + 3]);

		uint16_t c5 = c1 ^ c3;
		uint16_t c6 = c2 ^ c4;

		uint16_t c7 = multiply(c5, subkeys[i * 6 + 4]);
		uint16_t c8 = c6 + c7;
		uint16_t c9 = multiply(c8, subkeys[i * 6 + 5]);
		uint16_t c10 = c7 + c9;

		uint16_t S0, S1, S2, S3;

		S0 = c1 ^ c9;
		S1 = c3 ^ c9;
		S2 = c2 ^ c10;
		S3 = c4 ^ c10;

		if (i != 7) {
			uint16_t aux;
			aux = S2;
			S2  = S1;
			S1  = aux;
		}

		X0 = S0;
		X1 = S2;
		X2 = S1;
		X3 = S3;
	}

	// Runda 8.5
	uint16_t c1 = multiply(X0, subkeys[48 + 0]);
	uint16_t c2 = X1 + subkeys[48 + 1];
	uint16_t c3 = X2 + subkeys[48 + 2];
	uint16_t c4 = multiply(X3, subkeys[48 + 3]);

	set_encrypted_data(encrypted_data, c1, c2, c3, c4);
}

int main(int argc, char** argv) {
	char* key;
	char* data;
	char* encrypted_data;
	char** subkeys;

	// Alocare memorie pentru variabile
	alloc_memory(&key, &data, &encrypted_data, &subkeys);

	// Setarea valorilor
	set_values(&key, &data);
	
	// Calcularea cheilor
	compute_subkeys(key, &subkeys);

	uint16_t* subkeys_16_t = (uint16_t*) malloc(sizeof(uint16_t) * SUBKEYS_NO);
	subkeys_to_uint16_t(subkeys, &subkeys_16_t);

	// Codificarea intrarii
	encrypt_data(data, &encrypted_data, subkeys_16_t);
	free(subkeys_16_t);

	// Afisarea datelor codificate
	print_encrypted_data(encrypted_data);

	// Eliberarea memoriei
	free_memory(&key, &data, &encrypted_data, &subkeys);

	return 0;
}