// license:BSD-3-Clause
// copyright-holders:Sven Schnelle
/***************************************************************************

  HP98629 LANIC Ethernet card

***************************************************************************/

#include "emu.h"
#include "hp98629.h"
#include "osdcomm.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <dirent.h>
#include <climits>
#include <map>
#include <iomanip>
#include <string>

#define LOG_LEVEL_REG 0x01
#define LOG_LEVEL_RING 0x02
#define LOG_LEVEL_CMD 0x04
#define LOG_LEVEL_CMD2 0x08
#define LOG_LEVEL_DUMP 0x10
#define LOG_LEVEL_ALL 0x1f
#define VERBOSE 0
#include "logmacro.h"

DEFINE_DEVICE_TYPE(HPDIO_98629, bus::hp_dio::dio16_98629_device, "dio98629", "HP98629A SRM card")

namespace bus::hp_dio {

void dio16_98629_device::device_add_mconfig(machine_config &config)
{
}

dio16_98629_device::dio16_98629_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
	dio16_98629_device(mconfig, HPDIO_98629, tag, owner, clock)
{
}

dio16_98629_device::dio16_98629_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock) :
	device_t(mconfig, type, tag, owner, clock),
	device_dio16_card_interface(mconfig, *this),
	m_switches{*this, "switches"},
	file_id{1}
{
}

static INPUT_PORTS_START(hp98629_port)
	PORT_START("switches")
	PORT_DIPNAME(REG_HP98629_SWITCHES_REMOTE, 0x00, "Remote")
	PORT_DIPSETTING(0x00, DEF_STR(Off))
	PORT_DIPSETTING(REG_HP98629_SWITCHES_REMOTE, DEF_STR(On))

	PORT_DIPNAME(REG_HP98629_SWITCHES_INT_LEVEL_MASK << REG_HP98629_SWITCHES_INT_LEVEL_SHIFT, 0x00 << REG_HP98629_SWITCHES_INT_LEVEL_SHIFT, "Interrupt level")
	PORT_DIPSETTING(0 << REG_HP98629_SWITCHES_INT_LEVEL_SHIFT, "3")
	PORT_DIPSETTING(1 << REG_HP98629_SWITCHES_INT_LEVEL_SHIFT, "4")
	PORT_DIPSETTING(2 << REG_HP98629_SWITCHES_INT_LEVEL_SHIFT, "5")
	PORT_DIPSETTING(3 << REG_HP98629_SWITCHES_INT_LEVEL_SHIFT, "6")

	PORT_DIPNAME(REG_HP98629_SWITCHES_SELECT_CODE_MASK << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, 21 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "Select code")
	PORT_DIPSETTING(0 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "0")
	PORT_DIPSETTING(1 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "1")
	PORT_DIPSETTING(2 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "2")
	PORT_DIPSETTING(3 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "3")
	PORT_DIPSETTING(4 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "4")
	PORT_DIPSETTING(5 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "5")
	PORT_DIPSETTING(6 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "6")
	PORT_DIPSETTING(7 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "7")
	PORT_DIPSETTING(8 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "8")
	PORT_DIPSETTING(9 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "9")
	PORT_DIPSETTING(10 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "10")
	PORT_DIPSETTING(11 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "11")
	PORT_DIPSETTING(12 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "12")
	PORT_DIPSETTING(13 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "13")
	PORT_DIPSETTING(14 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "14")
	PORT_DIPSETTING(15 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "15")
	PORT_DIPSETTING(16 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "16")
	PORT_DIPSETTING(17 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "17")
	PORT_DIPSETTING(18 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "18")
	PORT_DIPSETTING(19 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "19")
	PORT_DIPSETTING(20 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "20")
	PORT_DIPSETTING(21 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "21")
	PORT_DIPSETTING(22 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "22")
	PORT_DIPSETTING(23 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "23")
	PORT_DIPSETTING(24 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "24")
	PORT_DIPSETTING(25 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "25")
	PORT_DIPSETTING(26 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "26")
	PORT_DIPSETTING(27 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "27")
	PORT_DIPSETTING(28 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "28")
	PORT_DIPSETTING(29 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "29")
	PORT_DIPSETTING(30 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "30")
	PORT_DIPSETTING(31 << REG_HP98629_SWITCHES_SELECT_CODE_SHIFT, "31")
INPUT_PORTS_END

ioport_constructor dio16_98629_device::device_input_ports() const
{
	return INPUT_PORTS_NAME(hp98629_port);
}

void dio16_98629_device::hexdump(const char *pfx, void *_d, int s)
{
#if VERBOSE & LOG_LEVEL_DUMP
	const uint8_t *d = (uint8_t *)_d;
	char buf[128], *p;
	int i, j;

	for(i = 0; i < s; i += 16) {
		memset(buf, 0, sizeof(buf));
		p = buf;
		p += sprintf(p, "%s %04X: ", pfx, i);
		for(j = i; j < i + 16; j++) {
			if (j - i == 4 || j - i == 12)
				p += sprintf(p, " ");

			if (j - i == 8)
				p += sprintf(p, "  ");
			if (j < s)
				p += sprintf(p, " %02X", d[j]);
			else
				p += sprintf(p, "   ");
		}
		p += sprintf(p, "   ");
		for(j = i; j < s && j < i + 16; j++) {
			char c = d[j];
			if (c < 0x20)
				c = '.';
			p += sprintf(p, "%c", c);
		}
		LOGMASKED(LOG_LEVEL_CMD, "%s\n", buf);
	}
#endif
}

void dio16_98629_device::device_start()
{
	save_item(NAME(m_sc));
	save_item(NAME(m_installed_io));
	save_item(NAME(m_ram));
	m_installed_io = false;
}

void dio16_98629_device::setup_desc(struct descriptor &desc, uint16_t offset, uint16_t length)
{
#define DESC_ADDR(_x) ((_x + 0x4000) >> 1)
	offset <<= 1;
	desc.buf_addr = DESC_ADDR(offset);
	desc.buf_size = length;
	desc.buf_fill = DESC_ADDR(offset);
	desc.buf_empty = DESC_ADDR(offset);
}

int dio16_98629_device::get_volume_name(int index, char *name, bool pad)
{
	struct dirent *dirent;
	int ret = -1, idx;
	size_t len;
	char *endp;
	DIR *dir;

	dir = opendir("SRM");
	if (!dir)
		return -1;

	while ((dirent = readdir(dir))) {
		idx = strtoul(dirent->d_name, &endp, 10);
		if (*endp != ':' || index != idx)
			continue;
		LOGMASKED(LOG_LEVEL_CMD, "%s: directory %s, endp %s, index %d, wanted %d\n", __func__,
			  dirent->d_name, endp+1, idx, index);
		memset(name, pad ? ' ' : '\0', SRM_VOLNAME_LENGTH);
		len = strlen(endp+1);
		if (len > SRM_VOLNAME_LENGTH)
			len = SRM_VOLNAME_LENGTH;
		memcpy(name, endp+1, len);
		ret = 0;
		break;
	}
	closedir(dir);
	return ret;
}

int dio16_98629_device::get_volume_idx(char *name, int *index)
{
	struct dirent *dirent;
	int ret = -1, idx;
	char *endp;
	DIR *dir;

	dir = opendir("SRM");
	if (!dir)
		return -1;

	while ((dirent = readdir(dir))) {
		idx = strtoul(dirent->d_name, &endp, 10);
		if (*endp != ':')
			continue;
		if (!strncmp(endp+1, name, SRM_VOLNAME_LENGTH)) {
			LOGMASKED(LOG_LEVEL_CMD, "%s: directory [%s], endp %s, index %d, wanted [%s]\n",
				 __func__, dirent->d_name, endp+1, idx, name);
			ret = 0;
			*index = idx;
			break;
		}
	}
	closedir(dir);
	return ret;
}

bool dio16_98629_device::get_filename(std::string &filename, int start, int sets,
				      struct srm_file_name_set *filenames,
				      struct srm_volume_header *vh,
				      struct srm_file_header *fh)
{
	char name[32], *p;
	int addr = swapendian_int32(vh->device_address.address1);
	int present = swapendian_int32(vh->device_address_present);
	int wd = swapendian_int32(fh->working_directory);
	open_file_entry *entry = NULL;
	char addrs[16];

	if (wd > 0) {
		try {
			entry = &filemap.at(wd);
		} catch (std::out_of_range &e) {
			logerror("working directory not present: %d\n", wd);
			return false;
		}
	}

		LOGMASKED(LOG_LEVEL_CMD2, "%s: addr present %d, addr %d, wd=%d, name [%s], %s\n", __func__,
			  present, addr, wd, vh->volume_name, entry ? entry->filename.c_str() : "");

	if (wd > 0 && entry) {
		filename.append(entry->filename.c_str());
	} else if (present) {
		if (get_volume_name(addr, name, false)) {
			logerror("%s: failed to get volume %d\n", __func__, addr);
			return false;
		}
		sprintf(addrs, "SRM/%02d:", addr);
		filename.append(addrs);
		filename.append(name);
	} else {
		memcpy(name, vh->volume_name, SRM_VOLNAME_LENGTH);
		if ((p = (char *)memchr(name, ' ', SRM_VOLNAME_LENGTH)))
			*p = '\0';
		if (get_volume_idx(name, &addr)) {
			logerror("%s: failed to get volume %s\n", __func__, addr);
			return false;
		}
		sprintf(addrs, "SRM/%02d:", addr);
		filename.append(addrs);
		filename.append(name);
	}

	for(int i = start; i < start + sets; i++) {
		filename.push_back('/');
		char *s = filenames[i].file_name;
		int j = 0;
		while(*s != ' ' && *s != '<' && *s != '>' && j++ < 16)
			filename.push_back(*s++);
	}
	return true;
}

int dio16_98629_device::get_lif_info(int fd, uint16_t &out, uint32_t &bootaddr, size_t &hdr_offset)
{
	struct lif_header hdr;
	char buf[8];

	hdr_offset = 0;

	if (read(fd, buf, sizeof(buf)) != sizeof(buf))
		return -1;

	if (!strncmp(buf+2, "HFSLIF", 6)) {
		if (lseek(fd, 0x100, SEEK_SET) == -1)
			return -1;
		hdr_offset = 0x1e0;
	} else {
		if (lseek(fd, 0, SEEK_SET) == -1)
			return -1;
	}

	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
		return -1;

	hdr_offset += 0x20;
	out = swapendian_int16(hdr.type);
	bootaddr = swapendian_int32(hdr.gp);
	return 0;
}

int dio16_98629_device::errno_to_srm_error(int _errno)
{
	switch(_errno) {
	case ENOENT:
		return SRM_ERRNO_FILE_NOT_FOUND;
	case EPERM:
	case EACCES:
		return SRM_ERRNO_ACCESS_TO_FILE_NOT_ALLOWED;
	case EISDIR:
		return 0;
	case EIO:
		return SRM_ERRNO_VOLUME_IO_ERROR;
	default:
		LOGMASKED(LOG_LEVEL_CMD, "%s: unhandled errno %d (%s)\n",
			  __func__, _errno, strerror(_errno));
		return SRM_ERRNO_SOFTWARE_BUG;
	}
}

void dio16_98629_device::append_rx_control(uint8_t *data, int len)
{
	int start = m_desc->rx_control.buf_addr & 0x1fff;
	int offset = m_desc->rx_control.buf_fill & 0x1fff;
	int size = m_desc->rx_control.buf_size & 0x1fff;

	offset &= size-1;
	for(int i = 0; i < len; i++) {
		m_ram[start + offset] = data[i];
		LOGMASKED(LOG_LEVEL_RING, "%s: put %02x @ %04x\n",
			  __func__, data[i], start + offset);
		++offset &= size-1;
	}
	m_desc->rx_control.buf_fill = m_desc->rx_control.buf_addr + offset;
	m_sc |= REG_HP98629_SC_IP;
	update_int();
}

void dio16_98629_device::append_rx_data(void *_data, int len)
{
	uint8_t *data = static_cast<uint8_t *>(_data);
	int start = m_desc->rx_data.buf_addr & 0x1fff;
	int offset = m_desc->rx_data.buf_fill & 0x1fff;
	int size = m_desc->rx_data.buf_size & 0x1fff;

	hexdump("RESP", _data, len);
	offset &= size-1;
	for(int i = 0; i < len; i++) {
		m_ram[start + offset] = data[i];
		LOGMASKED(LOG_LEVEL_RING, "%s: put %02x @ %04x\n",
			  __func__, data[i], start + offset);
		++offset &= size-1;
	}

	m_desc->rx_data.buf_fill = m_desc->rx_data.buf_addr + offset;

	uint8_t ctrl[4] = {
		(uint8_t)(m_desc->rx_data.buf_fill & 0xff),
		(uint8_t)(m_desc->rx_data.buf_fill >> 8),
		0x05,
		0x01
	};
	append_rx_control(ctrl, 4);
}

int dio16_98629_device::get_file_info(std::string &filename, struct srm_file_info *fi)
{
	struct stat stbuf;
	uint16_t lif_type = 0xffff;
	uint32_t bootaddr = 0;
	size_t hdr_offset;

	if (lstat(filename.c_str(), &stbuf) == -1)
		return -1;

	if (S_ISREG(stbuf.st_mode)) {
		int fd = open(filename.c_str(), O_RDONLY);
		if (fd == -1)
			return -1;
		get_lif_info(fd, lif_type, bootaddr, hdr_offset);
		close(fd);
		fi->perm = swapendian_int16(stbuf.st_mode & 0777);
		fi->max_record_size = swapendian_int32(256);
		fi->logical_eof = swapendian_int32(stbuf.st_size > hdr_offset ? (stbuf.st_size - hdr_offset) : 0);
		fi->physical_size = swapendian_int32(stbuf.st_size > hdr_offset ? (stbuf.st_size - hdr_offset) : 0);
	} else if (S_ISDIR(stbuf.st_mode)) {
		lif_type = 0xff03;
		fi->record_mode = swapendian_int32(1);
		fi->share_code = swapendian_int32(1);
		fi->perm = swapendian_int16(stbuf.st_mode & 0777);
		fi->max_record_size = swapendian_int32(1);
		fi->logical_eof = swapendian_int32(1024);
		fi->physical_size = swapendian_int32(1024);
	} else {
		return -1;
	}

	fi->file_code = swapendian_int32(0xffff0000 | lif_type);
	fi->max_file_size = swapendian_int32(-1);
	fi->perm = swapendian_int16(stbuf.st_mode & 0777);
	fi->last_access.id = swapendian_int16(stbuf.st_gid);
	fi->creation_date.id = swapendian_int16(stbuf.st_uid);
	struct tm *tma = localtime(&stbuf.st_mtim.tv_sec);
	fi->last_access.date = swapendian_int16(((tma->tm_mon+1) << 12) | (tma->tm_mday << 7) | tma->tm_year);
	fi->last_access.seconds_since_midnight = swapendian_int32(tma->tm_hour * 3600 + tma->tm_min * 60 + tma->tm_sec);
	tma = localtime(&stbuf.st_ctim.tv_sec);
	fi->creation_date.date = swapendian_int16(((tma->tm_mon+1) << 12) | (tma->tm_mday << 7) | tma->tm_year);
	fi->creation_date.seconds_since_midnight = swapendian_int32(tma->tm_hour * 3600 + tma->tm_min * 60 + tma->tm_sec);
	memset(fi->filename, ' ', sizeof(fi->filename));
	std::string::size_type pos = filename.find_last_of("/");
	if (pos != std::string::npos)
		strncpy(fi->filename, filename.substr(pos+1, 16).c_str(), filename.substr(pos+1, 16).length());
	else
		strncpy(fi->filename, filename.c_str(), filename.length());
	return 0;
}

void dio16_98629_device::srm_send_response(void *request, void *response, int len, int level, int srm_errno)
{
	struct srm_send_header *p = static_cast<srm_send_header *>(request);
	struct srm_return_header *hdr = static_cast<srm_return_header *>(response);

	hdr->level = 7;
	hdr->message_length = swapendian_int32(len - 4);
	hdr->return_request_type = swapendian_int32(-swapendian_int32(p->request_type));
	hdr->user_sequencing_field = p->user_sequencing_field;
	hdr->status = swapendian_int32(srm_errno);
#if 0
	LOGMASKED(LOG_LEVEL_CMD, "%s: level %d, length %d, request type %x, sequence %x status %d\n",
		  __func__,
		  hdr->level,
		  swapendian_int32(hdr->message_length),
		  -swapendian_int32(hdr->return_request_type),
		  swapendian_int32(hdr->user_sequencing_field),
		  swapendian_int32(hdr->status));
#endif
	append_rx_data(response, len);
}

void dio16_98629_device::handle_srm_write(uint8_t *hbuf)
{
	struct srm_return_write ret{0};
	srm_write *p = reinterpret_cast<srm_write *>(hbuf);
	uint32_t offset = swapendian_int32(p->offset);
	uint32_t requested = swapendian_int32(p->requested);
	uint32_t id = swapendian_int32(p->file_id);
	uint32_t acc = swapendian_int32(p->access_code);
	size_t hdr_offset, len;
	int fd;

	LOGMASKED(LOG_LEVEL_CMD, "%s: WRITE offset=%x, requested = %d, acc=%d\n", __func__, offset, requested, acc);
	try {
		open_file_entry &entry = filemap.at(id);
		hdr_offset = entry.hdr_offset;
		fd = entry.fd;
	} catch (std::out_of_range &e) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_INVALID_FILE_ID);
		return;
	}

	if ((acc == 0 && lseek(fd, offset + hdr_offset, SEEK_SET) == -1) ||
	    (len = write(fd, p->data, requested)) == -1) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	ret.actual = swapendian_int32(len);

	LOGMASKED(LOG_LEVEL_CMD2, "%s: WRITE len = %d\n", __func__, len);
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_read(uint8_t *hbuf)
{
	srm_read *p = reinterpret_cast<srm_read *>(hbuf);
	uint32_t requested = swapendian_int32(p->requested);
	uint32_t offset = swapendian_int32(p->offset);
	uint32_t id = swapendian_int32(p->file_id);
	uint32_t acc = swapendian_int32(p->access_code);
	struct srm_return_read ret{0};
	size_t hdr_offset;
	int fd;

	try {
		open_file_entry &entry = filemap.at(id);
		hdr_offset = entry.hdr_offset;
		fd = entry.fd;
	} catch (std::out_of_range &e) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_INVALID_FILE_ID);
		return;
	}
	LOGMASKED(LOG_LEVEL_CMD,
		  "%s: READ file id = %x size=%d offset=%x accesscode=%d, hdr_offset=%x\n", __func__,
		  fd, requested, offset, acc, hdr_offset);
	if (acc == 0) // RANDOM ACCESS
		lseek(fd, offset + hdr_offset, SEEK_SET);
	if (requested > 512)
		requested = 512;
	ssize_t len = ::read(fd, ret.data, requested);
	if (len == -1) {
		ret.hdr.status = swapendian_int32(errno_to_srm_error(errno));
		len = 0;
	}

	if (len > 0)
		ret.actual = swapendian_int32(len);
	LOGMASKED(LOG_LEVEL_CMD2, "%s: read %d bytes\n", __func__, len);
	int retlen = sizeof(ret) - 512 + len;
	if (len != requested) {
		srm_send_response(p, &ret, retlen, 7, SRM_ERRNO_EOF_ENCOUNTERED);
		return;
	}
	srm_send_response(p, &ret, retlen, 7);
}

void dio16_98629_device::handle_srm_position(uint8_t *hbuf)
{
	struct srm_return_empty ret{0};
	srm_position *p = reinterpret_cast<srm_position *>(hbuf);
	uint32_t offset = swapendian_int32(p->offset);
	uint8_t whence = p->position_type ? SEEK_CUR : SEEK_SET;
	uint32_t id = swapendian_int32(p->file_id);
	size_t hdr_offset;
	int fd;

	try {
		open_file_entry &entry = filemap.at(id);
		hdr_offset = entry.hdr_offset;
		fd = entry.fd;
	} catch (std::out_of_range &e) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_INVALID_FILE_ID);
		return;
	}

	if (whence == SEEK_SET)
		offset += hdr_offset;

	LOGMASKED(LOG_LEVEL_CMD, "%s: POSITION offset=%x, whence = %d\n", __func__, offset, whence);

	if (lseek(fd, offset, whence) == -1) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_set_eof(uint8_t *hbuf)
{
	struct srm_fileinfo *p = reinterpret_cast<srm_fileinfo *>(hbuf);
	struct srm_return_empty ret{0};

	LOGMASKED(LOG_LEVEL_CMD, "%s: SET EOF\n", __func__);
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_change_protect(uint8_t *hbuf)
{
	struct srm_fileinfo *p = reinterpret_cast<srm_fileinfo *>(hbuf);
	struct srm_return_empty ret{0};

	LOGMASKED(LOG_LEVEL_CMD, "%s: CHANGE PROTECT\n", __func__);
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_fileinfo(uint8_t *hbuf)
{
	struct srm_fileinfo *p = reinterpret_cast<srm_fileinfo *>(hbuf);
	int id = swapendian_int32(p->file_id);
	struct srm_return_fileinfo ret{0};

	LOGMASKED(LOG_LEVEL_CMD, "%s: FILEINFO %d\n", __func__, id);
	try {
		open_file_entry &entry = filemap.at(id);

		if (get_file_info(entry.filename, &ret.fi)) {
			srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
			return;
		}
	} catch (std::out_of_range &e) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_INVALID_FILE_ID);
		return;
	}

	ret.fi.open_flag = swapendian_int32(1);
	ret.fi.max_file_size = swapendian_int32(1024);
	ret.fi.max_record_size = swapendian_int32(1);
	ret.fi.share_code = -1;
	ret.fi.capabilities = -1;
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_close(uint8_t *hbuf)
{
	struct srm_close *p = reinterpret_cast<srm_close *>(hbuf);
	int id = swapendian_int32(p->file_id);
	struct srm_return_empty ret{0};
	int fd;

	try {
		fd = filemap.at(id).fd;
	} catch (std::out_of_range &e) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_INVALID_FILE_ID);
		return;
	}

	LOGMASKED(LOG_LEVEL_CMD, "%s: CLOSE %d\n", __func__, id);
	close(fd);
	filemap.erase(id);
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_open(uint8_t *hbuf)
{
	struct srm_file_open *p = reinterpret_cast<srm_file_open *>(hbuf);
	struct srm_return_file_open ret{0};
	uint16_t lif_type = 0;
	open_file_entry entry;
	struct ::stat stbuf{0};
	uint32_t sets, bootaddr = 0;
	std::string filename;

	sets = swapendian_int32(p->fh.file_name_sets);
	if (!get_filename(filename, 0, sets, p->filenames, &p->vh, &p->fh)) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_FILE_NOT_FOUND);
		return;
	}

	int fd = open(filename.c_str(), O_RDWR);
	if (fd == -1 && errno == EISDIR) {
		LOGMASKED(LOG_LEVEL_CMD, "%s: OPEN DIR %s\n", __func__, filename);
		fd = open(filename.c_str(), O_DIRECTORY);
		if (fd != -1) {
			LOGMASKED(LOG_LEVEL_CMD, "%s: sucesss, id = %d\n", __func__, file_id);
			ret.file_id = swapendian_int32(file_id);
			ret.file_code = swapendian_int32(0xffffff03);
			ret.record_mode = swapendian_int32(1);
			ret.max_file_size = swapendian_int32(1024);
			ret.max_record_size = swapendian_int32(1);
			ret.sec_ext_size = 128;
			ret.open_logical_eof = swapendian_int32(1024);
			ret.share_bits = -1;
			entry.filename = filename;
			entry.fd = fd;
			entry.hdr_offset = 0;
			filemap[file_id++] = entry;
			srm_send_response(p, &ret, sizeof(ret), 7);
			return;
		}
	}
	LOGMASKED(LOG_LEVEL_CMD, "%s: OPEN %s, fd = %d\n", __func__, filename, fd);
	if (fd == -1) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	if (fstat(fd, &stbuf) == -1) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	get_lif_info(fd, lif_type, bootaddr, entry.hdr_offset);
	if (lseek(fd, entry.hdr_offset, SEEK_SET) == -1) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	entry.filename = filename;
	entry.fd = fd;
	ret.file_code = swapendian_int32(0xffff0000 | lif_type);
	ret.file_id = swapendian_int32(file_id);
	ret.open_logical_eof = swapendian_int32(stbuf.st_size > entry.hdr_offset ? (stbuf.st_size - entry.hdr_offset) : 0);
	ret.boot_start_address = swapendian_int32(bootaddr);
	ret.max_file_size = swapendian_int32(INT_MAX);
	ret.max_record_size = swapendian_int32(256);
	//	ret.share_bits = -1;
	filemap[file_id++] = entry;
	srm_send_response(p, &ret, sizeof(ret), 7);
}

bool dio16_98629_device::read_directory(std::string &path,
					std::list<std::string> &names)
{
	DIR *dir = opendir(path.c_str());
	struct dirent *dirent = NULL;
	if (!dir)
		return false;

	while ((dirent = readdir(dir)))
		names.push_front(std::string(dirent->d_name));

	names.sort(std::less<std::string>());
	closedir(dir);
	return true;
}

void dio16_98629_device::handle_srm_catalog(uint8_t *hbuf)
{
	struct srm_catalog *p = reinterpret_cast<srm_catalog *>(hbuf);
	struct srm_return_catalog ret{0};
	int idx, max, sets, cnt = 0;
	std::string filename;
	std::list<std::string> names;

	max = swapendian_int32(p->max_num_files);
	idx = swapendian_int32(p->file_index);
	sets = swapendian_int32(p->fh.file_name_sets);

	if (!get_filename(filename, 0, sets, p->filenames, &p->vh, &p->fh)) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_FILE_NOT_FOUND);
		return;
	}

	LOGMASKED(LOG_LEVEL_CMD, "%s: %d CAT [%s] max=%d start_name sets=%d wd=%x\n",
		  __func__, idx, filename, max,
		  swapendian_int32(p->fh.file_name_sets),
		  swapendian_int32(p->fh.working_directory));

	if (!read_directory(filename, names)) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	int i = 0;
	for (auto &it: names) {
		if (i++ < idx)
			continue;
		if (i > idx + max)
			break;
		std::string fullname;
		fullname.append(filename);
		fullname.append("/");
		fullname.append(it);
		if (!get_file_info(fullname, &ret.fi[cnt]))
			cnt++;
	}
	ret.num_files = swapendian_int32(cnt);
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_createfile(uint8_t *hbuf)
{
	struct srm_create_file *p = reinterpret_cast<srm_create_file *>(hbuf);
	struct srm_return_empty ret{0};
	std::string filename;
	int fd, sets, type;

	sets = swapendian_int32(p->fh.file_name_sets);
	type = swapendian_int16(p->file_code >> 16);

	if (!get_filename(filename, 0, sets, p->filenames, &p->vh, &p->fh)) {
		logerror("%s: failed to get filename\n", __func__);
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_FILE_NOT_FOUND);
		return;
	}

	LOGMASKED(LOG_LEVEL_CMD, "%s: CREATE FILE: %s %x\n", __func__, filename, type);

	if (type == 3) {
		if (mkdir(filename.c_str(), 0755) == -1) {
			srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
			return;
		}
	} else {
		fd = open(filename.c_str(), O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (fd == -1) {
			srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
			return;
		}
		struct lif_header buf{0};
		memcpy(buf.name, "WS_FILE   ", 10);
		buf.type = p->file_code >> 16;
		buf.gp = p->boot_start_address;
		if (write(fd, &buf, sizeof(buf)) == -1 || close(fd) == -1) {
			srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
			return;
		}
	}
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_create_link(uint8_t *hbuf)
{
	struct srm_create_link *p = reinterpret_cast<srm_create_link *>(hbuf);
	struct srm_return_empty ret{0};
	std::string old_filename, new_filename;
	int old_sets, new_sets, purge, err;

	old_sets = swapendian_int32(p->fh_old.file_name_sets);
	if (!get_filename(old_filename, 0, old_sets, p->filenames, &p->vh, &p->fh_old)) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_FILE_NOT_FOUND);
		return;
	}

	new_sets = swapendian_int32(p->fh_new.file_name_sets);
	if (!get_filename(new_filename, old_sets, new_sets, p->filenames, &p->vh, &p->fh_new)) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_FILE_NOT_FOUND);
		return;
	}

	purge = swapendian_int32(p->purge_old_link);
	LOGMASKED(LOG_LEVEL_CMD, "%s: CREATELINK %s -> %s, purge %d\n", __func__, old_filename, new_filename, purge);

	if (purge)
		err = rename(old_filename.c_str(), new_filename.c_str());
	else
		err = link(old_filename.c_str(), new_filename.c_str());
	srm_send_response(p, &ret, sizeof(ret), 7, err ? errno_to_srm_error(errno) : 0);
}

void dio16_98629_device::srm_to_c_string(char *s)
{
	char *p = (char *)memchr(s, ' ', 16);
	if (*p)
		*p = '\0';
}

void dio16_98629_device::handle_srm_areyoualive(uint8_t *hbuf)
{
	struct srm_return_empty ret{0};
	srm_send_response(hbuf, &ret, sizeof(ret), 2, 0x01000000);
}

void dio16_98629_device::handle_srm_purgelink(uint8_t *hbuf)
{
	struct srm_purge_link *p = reinterpret_cast<srm_purge_link *>(hbuf);
	struct srm_return_empty ret{0};
	std::string filename;
	int sets;

	sets = swapendian_int32(p->fh.file_name_sets);
	if (!get_filename(filename, 0, sets, p->filenames, &p->vh, &p->fh)) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_FILE_NOT_FOUND);
		return;
	}
	LOGMASKED(LOG_LEVEL_CMD, "%s: PURGE LINK %s\n", __func__, filename);
	if (unlink(filename.c_str()) == -1)
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
	srm_send_response(p, &ret, sizeof(ret), 7);
}

void dio16_98629_device::handle_srm_volstatus(uint8_t *hbuf)
{
	struct srm_volume_status *p = reinterpret_cast<srm_volume_status *>(hbuf);
	struct srm_return_volume_status ret{0};
	uint32_t address;
	int index, err;

	srm_to_c_string(p->vh.driver_name);
	srm_to_c_string(p->vh.catalogue_organization);
	srm_to_c_string(p->vh.volume_name);
	address = swapendian_int32(p->vh.device_address.address1);

	LOGMASKED(LOG_LEVEL_CMD, "%s: VOLUME STATUS addr %d, haddr %d, unit %d, volume %d, driver %s catorg %s vname %s present %x\n",
		  __func__, address,
		  swapendian_int32(p->vh.device_address.haddress),
		  swapendian_int32(p->vh.device_address.unit_num),
		  swapendian_int32(p->vh.device_address.volume_num),
		  p->vh.driver_name,
		  p->vh.catalogue_organization,
		  p->vh.volume_name,
		  swapendian_int32(p->vh.device_address_present));

	err = SRM_ERRNO_VOLUME_NOT_FOUND;
	if (p->vh.device_address_present) {
		if (!get_volume_name(address, ret.volname, true)) {
			LOGMASKED(LOG_LEVEL_CMD, "volume %d exists\n", address);
			err = 0;
			ret.exist = 1;
			ret.srmux = 1;
		}
	} else {
		if (!get_volume_idx(p->vh.volume_name, &index)) {
			LOGMASKED(LOG_LEVEL_CMD, "volume [%s] exists\n", p->vh.volume_name);
			memcpy(ret.volname, p->vh.volume_name, SRM_VOLNAME_LENGTH);
			err = 0;
			ret.exist = 1;
			ret.srmux = 1;
		}
	}

	if (!err) {
		ret.exist = 1;
		ret.srmux = 1;
	}
	srm_send_response(p, &ret, sizeof(ret), 7, err);
}

void dio16_98629_device::handle_srm_xchg_open(uint8_t *hbuf)
{
	struct srm_xchg_open *p = reinterpret_cast<srm_xchg_open *>(hbuf);
	uint32_t id1 = swapendian_int32(p->file_id1);
	uint32_t id2 = swapendian_int32(p->file_id2);
	struct srm_return_header ret = { 0 };
	open_file_entry entry1, entry2;
	std::string tmpname;

	LOGMASKED(LOG_LEVEL_CMD, "XCHG OPEN: %d <-> %d\n", id1, id2);
	try {
		entry1 = filemap.at(id1);
		entry2 = filemap.at(id2);
	} catch (std::out_of_range &e) {
		srm_send_response(p, &ret, sizeof(ret), 7, SRM_ERRNO_INVALID_FILE_ID);
		return;
	}

	tmpname = entry2.filename;
	tmpname.append(".TMP");
	if (rename(entry1.filename.c_str(), tmpname.c_str()) == -1) {
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	if (rename(entry2.filename.c_str(), entry1.filename.c_str()) == -1) {
		rename(tmpname.c_str(), entry1.filename.c_str());
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	if (rename(tmpname.c_str(), entry2.filename.c_str()) == -1) {
		rename(entry1.filename.c_str(), entry2.filename.c_str());
		rename(tmpname.c_str(), entry1.filename.c_str());
		srm_send_response(p, &ret, sizeof(ret), 7, errno_to_srm_error(errno));
		return;
	}

	srm_send_response(p, &ret, sizeof(ret), 7);
}
void dio16_98629_device::handle_tx_control()
{
	int fill = m_desc->tx_data.buf_fill & 0x1fff;
	int empty = m_desc->tx_data.buf_empty & 0x1fff;
	int start = m_desc->tx_data.buf_addr & 0x1fff;
	int size = m_desc->tx_data.buf_size & 0x1fff;
	uint8_t hbuf[1024];

	LOGMASKED(LOG_LEVEL_RING, "%s: fill = %x, empty = %x start = %x\n", __func__, fill, empty, start);
	if (fill == empty) {
		LOG("%s: no data\n", __func__);
		return;
	}

	memset(hbuf, 0x55, sizeof(hbuf));
	if (fill > empty) {
		memcpy(hbuf, m_ram + empty, fill - empty);
		hexdump("REQ ", hbuf, fill - empty);
	} else {
		int len1 = size - (empty - start);
		int len2 = fill - start;
		memcpy(hbuf, m_ram + empty, len1);
		memcpy(hbuf + len1, m_ram + start, len2);
		hexdump("REQ ", hbuf, len1 + len2);
	}
	m_desc->tx_data.buf_empty = m_desc->tx_data.buf_fill;
	m_desc->tx_control.buf_empty = m_desc->tx_control.buf_fill;

	struct srm_send_header *hdr = reinterpret_cast<srm_send_header *>(&hbuf);
	int length = swapendian_int32(hdr->message_length);
	int reqtype = swapendian_int32(hdr->request_type);
	int sequence = swapendian_int32(hdr->user_sequencing_field);

	LOGMASKED(LOG_LEVEL_CMD2, "%s: request type %d, sequence %x\n", __func__, reqtype, sequence);
	switch(reqtype) {
	case SRM_REQ_RESET:
		break;

	case SRM_REQ_AREYOUALIVE:
		handle_srm_areyoualive(hbuf);
		break;

	case SRM_REQ_WRITE:
		handle_srm_write(hbuf);
		break;

	case SRM_REQ_POSITION:
		handle_srm_position(hbuf);
		break;

	case SRM_REQ_READ:
		handle_srm_read(hbuf);
		break;

	case SRM_REQ_SET_EOF:
		handle_srm_set_eof(hbuf);
		break;

	case SRM_REQ_FILEINFO:
		handle_srm_fileinfo(hbuf);
		break;

	case SRM_REQ_CLOSE:
		handle_srm_close(hbuf);
		break;

	case SRM_REQ_OPEN:
		handle_srm_open(hbuf);
		break;

	case SRM_REQ_CATALOG:
		handle_srm_catalog(hbuf);
		break;

	case SRM_REQ_CREATEFILE:
		handle_srm_createfile(hbuf);
		break;

	case SRM_REQ_CREATELINK:
		handle_srm_create_link(hbuf);
		break;

	case SRM_REQ_VOLSTATUS:
		handle_srm_volstatus(hbuf);
		break;

	case SRM_PURGE_LINK:
		handle_srm_purgelink(hbuf);
		break;

	case SRM_REQ_CHANGE_PROTECT:
		handle_srm_change_protect(hbuf);
		break;

	case SRM_REQ_XCHG_OPEN:
		handle_srm_xchg_open(hbuf);
		break;

	default:
		logerror("%s: unknown request %d, level %d, len %d\n", __func__, reqtype, hdr->level, length);
		abort();
		break;
	}

}

void dio16_98629_device::device_reset()
{
	if (!m_installed_io) {
		uint8_t code = (m_switches->read() >> REG_HP98629_SWITCHES_SELECT_CODE_SHIFT)
					& REG_HP98629_SWITCHES_SELECT_CODE_MASK;

		uint32_t baseaddr = 0x600000 + (code << 16);

		program_space().install_device(baseaddr, baseaddr + 0xffff,
			*this, &dio16_98629_device::addrmap);
		m_installed_io = true;
	}
	file_id = 1;
	m_sc = REG_HP98629_SC_IP | get_irq_line() << 4;
	m_intmask = REG_HP98629_INTMASK_ERROR;
	memset(m_ram, 0, sizeof(m_ram));
	m_intcond = 1;
	m_ram[7] = '9';
	m_ram[8] = '8';
	m_ram[9] = '6';
	m_ram[10] = '2';
	m_ram[11] = '9';
	m_ram[0x17] = 3;
	m_ram[5] = 0x21;
	m_ram[0x100] = 0x81;


	m_ram[0x103] = 0;
	m_ram[0x104] = 0x22;

	m_desc = reinterpret_cast<struct descriptor_list *>(&m_ram[0x200]);

	setup_desc(m_desc->tx_control, 0x600, 0x100);
	setup_desc(m_desc->rx_control, 0x700, 0x100);

	setup_desc(m_desc->tx_data, 0x800, 0x800);
	setup_desc(m_desc->rx_data, 0x1000, 0x800);
}

void dio16_98629_device::sc_w(uint16_t data)
{
	LOGMASKED(LOG_LEVEL_REG, "%s: %02x\n", __func__, data & 0xff);
	data &= REG_HP98629_SC_IE;
	m_sc &= ~REG_HP98629_SC_IE;

	m_sc |= data;
	update_int();
}

uint16_t dio16_98629_device::sc_r()
{
	LOGMASKED(LOG_LEVEL_REG, "%s: %02x\n", __func__, m_sc);
	return m_sc;
}

void dio16_98629_device::sem_w(uint16_t data)
{
	LOGMASKED(LOG_LEVEL_REG, "%s: %02x\n", __func__, data & 0xff);
	m_sem = data;
}

uint16_t dio16_98629_device::sem_r()
{
	LOGMASKED(LOG_LEVEL_REG, "%s: %02x\n", __func__, m_sem);
	return 0;
}

uint16_t dio16_98629_device::fw_id_r()
{
	LOGMASKED(LOG_LEVEL_REG, "%s: %02x\n", __func__, m_modem);
	return 3;
}

uint16_t dio16_98629_device::id_r()
{
	LOGMASKED(LOG_LEVEL_REG, "%s\n", __func__);
	return REG_HP98629_ID | (m_switches->read() & REG_HP98629_SWITCHES_REMOTE) | 0x80;
}

void dio16_98629_device::id_w(uint16_t data)
{
	LOGMASKED(LOG_LEVEL_REG, "%s (RESET)\n", __func__);
	reset();
}

int dio16_98629_device::get_irq_line()
{
	return (m_switches->read() >> REG_HP98629_SWITCHES_INT_LEVEL_SHIFT) & REG_HP98629_SWITCHES_INT_LEVEL_MASK;
}

void dio16_98629_device::update_int()
{
	const int line = get_irq_line() + 3;
	const bool state = (m_sc & (REG_HP98629_SC_IE|REG_HP98629_SC_IP)) == (REG_HP98629_SC_IE|REG_HP98629_SC_IP);
	LOGMASKED(LOG_LEVEL_REG, "%s: line %d, state %d m_sc %02x\n", __func__, line, state, m_sc);
	irq3_out(state && line == 3);
	irq4_out(state && line == 4);
	irq5_out(state && line == 5);
	irq6_out(state && line == 6);
}

void dio16_98629_device::ram_w(offs_t offset, uint16_t data, u16 mem_mask)
{
	uint32_t pc = 0;//program_space().device().state().pc();
	bool write;
	uint8_t cmd;
	const char *desc = "???", *member = "???";

	data &= 0xff;
	COMBINE_DATA(&m_ram[offset]);
	m_ram[COMMAND] = 0;
	switch(offset) {
	case INT_COND:
		LOGMASKED(LOG_LEVEL_REG, "%s: WRITE INT_COND %02x\n", __func__, data);
		break;
	case COMMAND:
		write = !(data & 0x80);
		cmd = data & 0x7f;
		switch(cmd) {
		case 0:
			if (write) {
				if (data & 0x80) {
					LOGMASKED(LOG_LEVEL_REG, "RESET %02x\n", data);
					reset();
				}
			} else {
				LOGMASKED(LOG_LEVEL_REG, "READ ID\n");
				m_ram[DATA_REG] = REG_HP98629_ID | \
					(m_switches->read() & REG_HP98629_SWITCHES_REMOTE) | 0x80;
			}
			break;
		case 1:
			if (!write) {
				m_ram[DATA_REG] = (m_sc & 0x80) ? 1 : 0;
				LOGMASKED(LOG_LEVEL_REG, "%s: INT STATUS %x\n", __func__, (m_sc & 0x80) ? 1 : 0);
			}
			break;
		case 2:
			if (!write) {
				LOGMASKED(LOG_LEVEL_REG, "%s: BUSY\n", __func__);
				m_ram[DATA_REG] = 0;
			}
			break;
		case 3:
			if (!write) {
				LOGMASKED(LOG_LEVEL_REG, "%s: FIRMWARE ID\n", __func__);
				m_ram[DATA_REG] = 3;
			}
			break;
		case 5:
			if (!write) {
				LOGMASKED(LOG_LEVEL_REG, "%s: RX STATUS\n", __func__);
				m_ram[DATA_REG] = 0; // XXX
			}
			break;
		case 6:
			if (!write) {
				LOGMASKED(LOG_LEVEL_REG, "%s: READ NODE ID\n", __func__);
				m_ram[DATA_REG] = 1;
			}
			break;
		case 7:
			if (!write) {
				LOGMASKED(LOG_LEVEL_REG, "%s: READ CRC ERRORS\n", __func__);
				m_ram[DATA_REG] = 0;
			}
			break;
		case 121:
			if (write) {
				LOGMASKED(LOG_LEVEL_REG, "SET INT_MASK = %02x\n", m_ram[DATA_REG]);
				m_intmask = m_ram[DATA_REG];
			} else {
				LOGMASKED(LOG_LEVEL_REG, "READ INT_MASK = %02x\n", m_intmask);
				m_ram[DATA_REG] = m_intmask;
			}
			break;
		default:
			LOGMASKED(LOG_LEVEL_REG, "UNKNOWN COMMAND: %x\n", cmd);
		}
		m_ram[COMMAND] = 0;
		break;
	case DATA_REG:
		LOGMASKED(LOG_LEVEL_REG, "%s: DATA_REG = %02x\n", __func__, data);
		break;
	case PRIMARY_ADDR:
		LOGMASKED(LOG_LEVEL_REG, "%s: PRIMARY_ADDR = %02x\n", __func__, data);
		break;
	case DSDPL:
		LOGMASKED(LOG_LEVEL_REG, "%s: DSDPL = %02x\n", __func__, data);
		break;
	case DSDPH:
		LOGMASKED(LOG_LEVEL_REG, "%s: DSDPH = %02x\n", __func__, data);
		break;
	case ERROR_CODE:
		LOGMASKED(LOG_LEVEL_REG, "%s: ERROR_CODE = %02x\n", __func__, data);
		break;
	default:
		if (offset >= 0x202 && offset <= 0x222) {
			if (offset >= 0x202 && offset <= 0x209) {
				desc = "tx_control";
			} else if (offset >= 0x20a && offset <= 0x211) {
				desc = "tx_data";
			} else if (offset >= 0x212 && offset <= 0x219) {
				desc = "rx_control";
			} else if (offset >= 0x21a && offset <= 0x222) {
				desc = "rx_data";
			}

			switch((offset % 8) >> 1) {
			case 0:
				member = "buf_empty";
				break;
			case 1:
				member = "buf_addr";
				break;
			case 2:
				member = "buf_size";
				break;
			case 3:
				member = "buf_fill";
			default:
				break;
			}
			LOGMASKED(LOG_LEVEL_REG, "%s: %08x %04x %s->%s = %02x\n", __func__, pc, offset,
				  desc, member, data);
		} else {
			LOGMASKED(LOG_LEVEL_REG, "%s: %08x %04x = %02x\n", __func__, pc, offset, data);
		}
		break;
	}
	if (offset == 0x207) {
		handle_tx_control();
	}
}

uint16_t dio16_98629_device::ram_r(offs_t offset)
{
	uint32_t pc = 0;//program_space().device().state().pc();
	const char *desc = "???", *member = "???";

	switch (offset) {
	case INT_COND:
		LOGMASKED(LOG_LEVEL_REG, "%s: INT_COND %02x\n", __func__, m_intcond);
		m_sc &= ~REG_HP98629_SC_IP;
		update_int();
		return m_intcond;
	case COMMAND:
		LOGMASKED(LOG_LEVEL_REG, "%s: COMMAND\n", __func__);
		return 0;
	case DATA_REG:
		LOGMASKED(LOG_LEVEL_REG, "%s: DATA_REG = %02x\n", __func__, m_ram[DATA_REG]);
		return m_ram[DATA_REG];
	case PRIMARY_ADDR:
		LOGMASKED(LOG_LEVEL_REG, "%s: PRIMARY_ADDR = %02x\n", __func__, m_ram[PRIMARY_ADDR]);
		return m_ram[PRIMARY_ADDR];

	default:
		if (offset >= 0x202 && offset <= 0x222) {
			if (offset >= 0x202 && offset <= 0x209) {
				desc = "tx_control";
			} else if (offset >= 0x20a && offset <= 0x211) {
				desc = "tx_data";
			} else if (offset >= 0x212 && offset <= 0x219) {
				desc = "rx_control";
			} else if (offset >= 0x21a && offset <= 0x222) {
				desc = "rx_data";
			}

			switch((offset % 8) >> 1) {
			case 0:
				member = "buf_empty";
				break;
			case 1:
				member = "buf_addr";
				break;
			case 2:
				member = "buf_size";
				break;
			case 3:
				member = "buf_fill";
			default:
				break;
			}
			if (offset & 1)
				LOGMASKED(LOG_LEVEL_REG, "%s: %08x %04x %s -> %s = %02x%02x\n", __func__, pc, offset,
					  desc, member, m_ram[offset], m_ram[offset-1]);
		} else {
			LOGMASKED(LOG_LEVEL_REG, "%s: %08x %04x => %02x\n", __func__, pc, offset, m_ram[offset]);
		}
		break;
	}
	return m_ram[offset];
}

void dio16_98629_device::addrmap(address_map &map)
{
	map(0x0000, 0x0001).rw(FUNC(dio16_98629_device::id_r), FUNC(dio16_98629_device::id_w));
	map(0x0002, 0x0003).rw(FUNC(dio16_98629_device::sc_r), FUNC(dio16_98629_device::sc_w));
	map(0x0004, 0x0005).rw(FUNC(dio16_98629_device::sem_r), FUNC(dio16_98629_device::sem_w));
	map(0x4000, 0xbfff).rw(FUNC(dio16_98629_device::ram_r), FUNC(dio16_98629_device::ram_w));
}

} // namespace bus::hp_dio
