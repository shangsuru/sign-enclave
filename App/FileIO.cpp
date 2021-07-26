#include "FileIO.h"

size_t get_file_size(const char *filename)
{
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.good())
  {
    std::cerr << "Failed to open the file \"" << filename << "\"" << std::endl;
    return -1;
  }
  ifs.seekg(0, std::ios::end);
  size_t size = (size_t)ifs.tellg();
  return size;
}

bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs.good())
  {
    std::cerr << "Failed to open the file \"" << filename << "\"" << std::endl;
    return false;
  }
  ifs.read(reinterpret_cast<char *>(buf), bsize);
  if (ifs.fail())
  {
    std::cerr << "Failed to read the file \"" << filename << "\"" << std::endl;
    return false;
  }
  return true;
}

bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ofstream ofs(filename, std::ios::binary | std::ios::out);
  if (!ofs.good())
  {
    std::cerr << "Failed to open the file \"" << filename << "\"" << std::endl;
    return false;
  }
  ofs.seekp(offset, std::ios::beg);
  ofs.write(reinterpret_cast<const char *>(buf), bsize);
  if (ofs.fail())
  {
    std::cerr << "Failed to write the file \"" << filename << "\"" << std::endl;
    return false;
  }

  return true;
}