// license:BSD-3-Clause
// copyright-holders:Andreas Naive,David Haywood
#ifndef _IGS036CRYPT_H_
#define _IGS036CRYPT_H_


class igs036_decryptor
{
public:
	igs036_decryptor(const uint8_t* game_key);
	void decrypter_rom(memory_region* region);
	uint16_t decrypt(uint16_t cipherword, int word_address)const;
	uint16_t deobfuscate(uint16_t cipherword, int word_address)const;

private:
	const uint8_t* key;

	static int (*rot_enabling[16][4])(int);
	static int (*rot_direction[4][8])(int);
	static const uint32_t triggers[16][2];

	int rotation(int address)const;
	uint16_t rol(uint16_t num, int shift)const;
	int rot_enabled(int address, const int* group)const ;
	int rot_group(int address, const int* group)const;
};

extern const uint8_t   m312cn_key[0x100];
extern const uint8_t  cjddzsp_key[0x100];
extern const uint8_t    cjdh2_key[0x100];
extern const uint8_t     kov3_key[0x100];
extern const uint8_t   ddpdoj_key[0x100];

#endif
