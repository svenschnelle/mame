// license:BSD-3-Clause
// copyright-holders:Nathan Woods
/***************************************************************************

    fs_coco_os9.cpp

    Management of CoCo OS-9 floppy images

    OS-9 Level 2 Technical Reference, Chapter 5, Random Block File Manager,
    page 2

    https://colorcomputerarchive.com/repo/Documents/Manuals/Operating%20Systems/OS-9%20Level%202%20Manual%20(Tandy).pdf

***************************************************************************/

#include "fs_coco_os9.h"
#include "coco_rawdsk.h"
#include "strformat.h"

namespace fs {

const coco_os9_image COCO_OS9;


//**************************************************************************
//  IMPLEMENTATION
//**************************************************************************

//-------------------------------------------------
//  name
//-------------------------------------------------

const char *coco_os9_image::name() const
{
	return "coco_os9";
}


//-------------------------------------------------
//  description
//-------------------------------------------------

const char *coco_os9_image::description() const
{
	return "CoCo OS-9";
}


//-------------------------------------------------
//  enumerate_f
//-------------------------------------------------

void coco_os9_image::enumerate_f(floppy_enumerator &fe, u32 form_factor, const std::vector<u32> &variants) const
{
	if (has(form_factor, variants, floppy_image::FF_525, floppy_image::SSDD))
	{
		fe.add(FLOPPY_COCO_RAWDSK_FORMAT, 161280, "coco_rawdsk_os9_35", "CoCo Raw Disk OS-9 single-sided 35 tracks");
		fe.add(FLOPPY_COCO_RAWDSK_FORMAT, 184320, "coco_rawdsk_os9_40", "CoCo Raw Disk OS-9 single-sided 40 tracks");
	}
}


//-------------------------------------------------
//  can_format
//-------------------------------------------------

bool coco_os9_image::can_format() const
{
	return true;
}


//-------------------------------------------------
//  can_read
//-------------------------------------------------

bool coco_os9_image::can_read() const
{
	return true;
}


//-------------------------------------------------
//  can_write
//-------------------------------------------------

bool coco_os9_image::can_write() const
{
	return false;
}


//-------------------------------------------------
//  has_rsrc
//-------------------------------------------------

bool coco_os9_image::has_rsrc() const
{
	return false;
}


//-------------------------------------------------
//  directory_separator
//-------------------------------------------------

char coco_os9_image::directory_separator() const
{
	return '/';
}


//-------------------------------------------------
//  volume_meta_description
//-------------------------------------------------

std::vector<meta_description> coco_os9_image::volume_meta_description() const
{
	std::vector<meta_description> results;
	results.emplace_back(meta_description(meta_name::name, "UNTITLED", false, [](const meta_value &m) { return m.as_string().size() <= 32; }, "Volume name, up to 32 characters"));
	results.emplace_back(meta_description(meta_name::creation_date, util::arbitrary_datetime::now(), false, nullptr, "Creation time"));
	return results;
}


//-------------------------------------------------
//  file_meta_description
//-------------------------------------------------

std::vector<meta_description> coco_os9_image::file_meta_description() const
{
	return entity_meta_description();
}


//-------------------------------------------------
//  directory_meta_description
//-------------------------------------------------

std::vector<meta_description> coco_os9_image::directory_meta_description() const
{
	return entity_meta_description();
}


//-------------------------------------------------
//  entity_meta_description
//-------------------------------------------------

std::vector<meta_description> coco_os9_image::entity_meta_description() const
{
	std::vector<meta_description> results;
	results.emplace_back(meta_description(meta_name::name, "", false, [](const meta_value &m) { return validate_filename(m.as_string()); }, "File name"));
	results.emplace_back(meta_description(meta_name::creation_date, util::arbitrary_datetime::now(), false, nullptr, "Creation time"));
	results.emplace_back(meta_description(meta_name::owner_id, 0, true, nullptr, "Owner ID"));
	results.emplace_back(meta_description(meta_name::attributes, "", true, nullptr, "File attributes"));
	results.emplace_back(meta_description(meta_name::length, 0, true, nullptr, "Size of the file in bytes"));
	return results;
}


//-------------------------------------------------
//  mount
//-------------------------------------------------

std::unique_ptr<filesystem_t> coco_os9_image::mount(fsblk_t &blockdev) const
{
	// read the header block
	blockdev.set_block_size(256);
	volume_header header(blockdev.get(0));

	// sanity checks
	if (header.sectors_per_track() != header.track_size_in_sectors())
		return { };

	// create the implementation
	return std::make_unique<impl>(blockdev, std::move(header));
}


//-------------------------------------------------
//  pick_os9_string
//-------------------------------------------------

std::string coco_os9_image::pick_os9_string(std::string_view raw_string)
{
	// find the last NUL or high bit character
	auto iter = std::find_if(raw_string.begin(), raw_string.end(), [](char ch)
	{
		return ch == '\0' || ch & 0x80;
	});

	// get the preliminary result
	std::string result(raw_string.begin(), iter);

	// and add the final character if we have to
	if (iter < raw_string.end() && *iter & 0x80)
		result.append(1, *iter & 0x7F);
	return result;

}


//-------------------------------------------------
//  to_os9_string
//-------------------------------------------------

std::string coco_os9_image::to_os9_string(std::string_view s, size_t length)
{
	std::string result(length, '\0');
	for (auto i = 0; i < std::min(length, s.size()); i++)
	{
		result[i] = (s[i] & 0x7F)
			| (i == s.size() ? 0x80 : 0x00);
	}
	return result;
}


//-------------------------------------------------
//  pick_integer_be
//-------------------------------------------------

u32 coco_os9_image::pick_integer_be(const u8 *data, int length)
{
	u32 result = 0;
	for (int i = 0; i < length; i++)
		result |= u32(data[length - i - 1]) << i * 8;
	return result;
}


//-------------------------------------------------
//  from_os9_date
//-------------------------------------------------

util::arbitrary_datetime coco_os9_image::from_os9_date(u32 os9_date, u16 os9_time)
{
	util::arbitrary_datetime dt;
	memset(&dt, 0, sizeof(dt));
	dt.year			= ((os9_date >> 16) & 0xFF) + 1900;
	dt.month		= (os9_date >> 8) & 0xFF;
	dt.day_of_month	= (os9_date >> 0) & 0xFF;
	dt.hour			= (os9_time >> 8) & 0xFF;
	dt.minute		= (os9_time >> 0) & 0xFF;
	return dt;
}


//-------------------------------------------------
//  to_os9_date
//-------------------------------------------------

std::tuple<u32, u16> coco_os9_image::to_os9_date(const util::arbitrary_datetime &datetime)
{
	u32 os9_date = ((datetime.year - 1900) & 0xFF) << 16
		| (datetime.month & 0xFF) << 8
		| (datetime.day_of_month & 0xFF) << 0;
	u16 os9_time = (datetime.hour & 0xFF) << 8
		| (datetime.minute & 0xFF) << 0;
	return std::make_tuple(os9_date, os9_time);
}


//-------------------------------------------------
//  validate_filename
//-------------------------------------------------

bool coco_os9_image::validate_filename(std::string_view name)
{
	return !is_ignored_filename(name)
		&& name.size() <= 29
		&& std::find_if(name.begin(), name.end(), [](const char ch) { return ch == '\0' || ch == '/' || ch >= 0x80; }) == name.end();
}


//-------------------------------------------------
//  is_ignored_filename - should this file name be
//  ignored if it is in the file system?
//-------------------------------------------------

bool coco_os9_image::is_ignored_filename(std::string_view name)
{
	return name.empty()
		|| name[0] == '\0'
		|| name == "."
		|| name == "..";
}


//-------------------------------------------------
//  volume_header ctor
//-------------------------------------------------

coco_os9_image::volume_header::volume_header(fsblk_t::block_t &&block)
	: m_block(std::move(block))
{
}


//-------------------------------------------------
//  volume_header::name
//-------------------------------------------------

std::string coco_os9_image::volume_header::name() const
{
	std::string_view raw_name((const char *)&m_block.rodata()[31], 32);
	return pick_os9_string(raw_name);
}


//-------------------------------------------------
//  file_header ctor
//-------------------------------------------------

coco_os9_image::file_header::file_header(fsblk_t::block_t &&block)
	: m_block(std::move(block))
{
}


//-------------------------------------------------
//  file_header::creation_date
//-------------------------------------------------

util::arbitrary_datetime coco_os9_image::file_header::creation_date() const
{
	return from_os9_date(m_block.r24b(13));
}


//-------------------------------------------------
//  file_header::metadata
//-------------------------------------------------

meta_data coco_os9_image::file_header::metadata() const
{
	// format the attributes
	std::string attributes = util::string_format("%c%c%c%c%c%c%c%c",
		is_directory()      ? 'd' : '-',
		is_non_sharable()   ? 's' : '-',
		is_public_execute() ? 'x' : '-',
		is_public_write()   ? 'w' : '-',
		is_public_read()    ? 'r' : '-',
		is_user_execute()   ? 'x' : '-',
		is_user_write()     ? 'w' : '-',
		is_user_read()      ? 'r' : '-');

	meta_data result;
	result.set(meta_name::creation_date,    creation_date());
	result.set(meta_name::owner_id,         owner_id());
	result.set(meta_name::attributes,       std::move(attributes));
	result.set(meta_name::length,           file_size());
	return result;
}


//-------------------------------------------------
//  file_header::get_sector_map_entry_count
//-------------------------------------------------

int coco_os9_image::file_header::get_sector_map_entry_count() const
{
	return (m_block.size() - 16) / 5;
}


//-------------------------------------------------
//  file_header::get_sector_map_entry
//-------------------------------------------------

void coco_os9_image::file_header::get_sector_map_entry(int entry_number, u32 &start_lsn, u16 &count) const
{
	start_lsn   = m_block.r24b(16 + (entry_number * 5) + 0);
	count       = m_block.r16b(16 + (entry_number * 5) + 3);
}


//-------------------------------------------------
//  impl ctor
//-------------------------------------------------

coco_os9_image::impl::impl(fsblk_t &blockdev, volume_header &&header)
	: filesystem_t(blockdev, 256)
	, m_volume_header(std::move(header))
{
}


//-------------------------------------------------
//  impl::metadata
//-------------------------------------------------

meta_data coco_os9_image::impl::metadata()
{
	meta_data results;
	results.set(meta_name::name, m_volume_header.name());
	results.set(meta_name::creation_date, m_volume_header.creation_date());
	return results;
}


//-------------------------------------------------
//  impl::root
//-------------------------------------------------

filesystem_t::dir_t coco_os9_image::impl::root()
{
	if (!m_root)
		m_root = open_directory(m_volume_header.root_dir_lsn());
	return m_root.strong();
}


//-------------------------------------------------
//  impl::drop_root_ref
//-------------------------------------------------

void coco_os9_image::impl::drop_root_ref()
{
	m_root = nullptr;
}


//-------------------------------------------------
//  impl::format
//-------------------------------------------------

void coco_os9_image::impl::format(const meta_data &meta)
{
	// for some reason, the OS-9 world favored filling with 0xE5
	m_blockdev.fill(0xE5);

	// identify geometry info
	u8 sectors = 18;				// TODO - we need a definitive technique to get the floppy geometry
	u8 heads = 1;					// TODO - we need a definitive technique to get the floppy geometry
	u16 sector_bytes = 256;			// TODO - we need a definitive technique to get the floppy geometry
	bool is_double_density = true;	// TODO - we need a definitive technique to get the floppy geometry
	u32 tracks = m_blockdev.block_count() / sectors / heads;

	// get attributes from metadata
	std::string volume_title					= meta.get_string(meta_name::name, "UNTITLED");
	util::arbitrary_datetime creation_datetime	= meta.get_date(meta_name::creation_date);
	auto [creation_os9date, creation_os9time] = to_os9_date(creation_datetime);

	u32 lsn_count = m_blockdev.block_count();
	u16 cluster_size = 1;
	u16 owner_id = 1;
	u16 disk_id = 1;
	u8 attributes = 0;
	u32 allocation_bitmap_bits = lsn_count / cluster_size;
	u32 allocation_bitmap_lsns = (allocation_bitmap_bits / 8 + sector_bytes - 1) / sector_bytes;
	u8 format_flags = ((heads > 1) ? 0x01 : 0x00)
		| (is_double_density ? 0x02 : 0x00);

	// volume header
	auto volume_header = m_blockdev.get(0);
	volume_header.fill(0x00);
	volume_header.w24b(0, lsn_count);								// DD.TOT - total secctors
	volume_header.w8(3, sectors);									// DD.TKS - track size in sectors
	volume_header.w16b(4, (allocation_bitmap_bits + 7) / 8);		// DD.MAP - allocation bitmap in bytes
	volume_header.w16b(6, cluster_size);							// DD.BIT - cluster size
	volume_header.w24b(8, 1 + allocation_bitmap_lsns);				// DD.DIR - root directory LSN
	volume_header.w16b(11, owner_id);								// DD.OWN - owner ID
	volume_header.w8(13, attributes);								// DD.ATT - Dattributes
	volume_header.w16b(14, disk_id);								// DD.DSK - disk ID
	volume_header.w8(16, format_flags);								// DD.FMT - format flags
	volume_header.w16b(17, sectors);								// DD.SPT - sectors per track
	volume_header.w24b(26, creation_os9date);						// DD.DAT - date of creation
	volume_header.w16b(29, creation_os9time);						// DD.DAT - time of creation
	volume_header.wstr(31, to_os9_string(volume_title, 32));		// DD.NAM - title
	volume_header.w16b(103, sector_bytes / 256);					// sector bytes

	// path descriptor options
	volume_header.w8(0x3f + 0x00, 1);								// device class
	volume_header.w8(0x3f + 0x01, 1);								// drive number
	volume_header.w8(0x3f + 0x03, 0x20);							// device type
	volume_header.w8(0x3f + 0x04, 1);								// density capability
	volume_header.w16b(0x3f + 0x05, tracks);						// number of tracks
	volume_header.w8(0x3f + 0x07, heads);							// number of sides
	volume_header.w16b(0x3f + 0x09, sectors);						// sectors per track
	volume_header.w16b(0x3f + 0x0b, sectors);						// sectors on track zero
	volume_header.w8(0x3f + 0x0d, 3);								// sector interleave factor
	volume_header.w8(0x3f + 0x0e, 8);								// default sectors per allocation

	// allocation bitmap
	u32 total_allocated_sectors = 1 + allocation_bitmap_lsns + 1 + 8;
	std::vector<u8> abblk_bytes;
	abblk_bytes.resize(sector_bytes);
	for (u32 i = 0; i < allocation_bitmap_lsns; i++)
	{
		for (u32 j = 0; j < sector_bytes; j++)
		{
			u32 pos = (i * sector_bytes + j) * 8;
			if (pos + 8 < total_allocated_sectors)
				abblk_bytes[j] = 0xFF;
			else if (pos >= total_allocated_sectors)
				abblk_bytes[j] = 0x00;
			else
				abblk_bytes[j] = ~((1 << (8 - total_allocated_sectors + pos)) - 1);
		}

		auto abblk = m_blockdev.get(1 + i);
		abblk.copy(0, abblk_bytes.data(), sector_bytes);
	}

	// root directory header
	auto roothdr_blk = m_blockdev.get(1 + allocation_bitmap_lsns);
	roothdr_blk.fill(0x00);
	roothdr_blk.w8(0x00, 0xBF);
	roothdr_blk.w8(0x01, 0x00);
	roothdr_blk.w8(0x02, 0x00);
	roothdr_blk.w24b(0x03, creation_os9date);
	roothdr_blk.w16b(0x06, creation_os9time);
	roothdr_blk.w8(0x08, 0x01);
	roothdr_blk.w8(0x09, 0x00);
	roothdr_blk.w8(0x0A, 0x00);
	roothdr_blk.w8(0x0B, 0x00);
	roothdr_blk.w8(0x0C, 0x40);
	roothdr_blk.w24b(0x0D, creation_os9date);
	roothdr_blk.w24b(0x10, 1 + allocation_bitmap_lsns + 1);
	roothdr_blk.w16b(0x13, 8);

	// root directory data
	auto rootdata_blk = m_blockdev.get(1 + allocation_bitmap_lsns + 1);
	rootdata_blk.fill(0x00);
	rootdata_blk.w8(0x00, 0x2E);
	rootdata_blk.w8(0x01, 0xAE);
	rootdata_blk.w8(0x1F, 1 + allocation_bitmap_lsns);
	rootdata_blk.w8(0x20, 0xAE);
	rootdata_blk.w8(0x3F, 1 + allocation_bitmap_lsns);
}


//-------------------------------------------------
//  impl::open_directory
//-------------------------------------------------

coco_os9_image::impl::directory *coco_os9_image::impl::open_directory(u32 lsn)
{
	file_header header(m_blockdev.get(lsn));
	return new directory(*this, std::move(header));
}


//-------------------------------------------------
//  impl::read_file_data
//-------------------------------------------------

std::vector<u8> coco_os9_image::impl::read_file_data(const file_header &header) const
{
	std::vector<u8> data;
	data.reserve(header.file_size());
	int entry_count = header.get_sector_map_entry_count();
	for (int i = 0; i < entry_count; i++)
	{
		u32 start_lsn;
		u16 count;
		header.get_sector_map_entry(i, start_lsn, count);

		for (u32 lsn = start_lsn; lsn < start_lsn + count; lsn++)
		{
			auto block = m_blockdev.get(lsn);
			size_t block_size = std::min(std::min(u32(m_volume_header.sector_size()), block.size()), header.file_size() - u32(data.size()));
			for (auto i = 0; i < block_size; i++)
				data.push_back(block.rodata()[i]);
		}
	}
	return data;
}


//-------------------------------------------------
//  file ctor
//-------------------------------------------------

coco_os9_image::impl::file::file(impl &i, file_header &&file_header)
	: m_fs(i)
	, m_file_header(std::move(file_header))
{
}


//-------------------------------------------------
//  file::drop_weak_references
//-------------------------------------------------

void coco_os9_image::impl::file::drop_weak_references()
{
}


//-------------------------------------------------
//  file::metadata
//-------------------------------------------------

meta_data coco_os9_image::impl::file::metadata()
{
	return m_file_header.metadata();
}


//-------------------------------------------------
//  file::read_all
//-------------------------------------------------

std::vector<u8> coco_os9_image::impl::file::read_all()
{
	return m_fs.read_file_data(m_file_header);
}


//-------------------------------------------------
//  directory ctor
//-------------------------------------------------

coco_os9_image::impl::directory::directory(impl &i, file_header &&file_header)
	: m_fs(i)
	, m_file_header(std::move(file_header))
{
}


//-------------------------------------------------
//  directory::drop_weak_references
//-------------------------------------------------

void coco_os9_image::impl::directory::drop_weak_references()
{
}


//-------------------------------------------------
//  directory::metadata
//-------------------------------------------------

meta_data coco_os9_image::impl::directory::metadata()
{
	return m_file_header.metadata();
}


//-------------------------------------------------
//  directory::contents
//-------------------------------------------------

std::vector<dir_entry> coco_os9_image::impl::directory::contents()
{
	// read the directory data
	std::vector<u8> directory_data = m_fs.read_file_data(m_file_header);

	// and assemble results
	std::vector<dir_entry> results;
	int directory_count = directory_data.size() / 32;
	for (int i = 0; i < directory_count; i++)
	{
		// determine the filename
		std::string_view raw_filename((const char *) &directory_data[i * 32], 29);
		std::string filename = pick_os9_string(raw_filename);
		if (is_ignored_filename(filename))
			continue;

		// determine the entry type
		u32 lsn = pick_integer_be(&directory_data[i * 32] + 29, 3);
		file_header file_header(m_fs.m_blockdev.get(lsn));
		dir_entry_type entry_type = file_header.is_directory()
			? dir_entry_type::dir
			: dir_entry_type::file;

		// and return the results
		results.emplace_back(std::move(filename), entry_type, lsn);
	}
	return results;
}


//-------------------------------------------------
//  directory::file_get
//-------------------------------------------------

filesystem_t::file_t coco_os9_image::impl::directory::file_get(u64 key)
{
	file_header header(m_fs.m_blockdev.get(u32(key)));
	return file_t(new file(m_fs, std::move(header)));
}


//-------------------------------------------------
//  directory::dir_get
//-------------------------------------------------

filesystem_t::dir_t coco_os9_image::impl::directory::dir_get(u64 key)
{
	return dir_t(m_fs.open_directory(u32(key)));
}

} // namespace fs
