#include "../TestDefinition.h"
#include "X509Decoder.h"
#include <fstream>
#include <GeneralUtils.h>

PTF_TEST_CASE(X509DecodeTest) {
	std::ifstream file(R"(D:\Documents\Elad\PcapPlusPlus\test.der)", std::ios::binary);

	const std::vector<uint8_t> rawData = {(std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()};
	std::cout << pcpp::byteArrayToHexString(rawData.data(), rawData.size()) << std::endl;
	auto decoder = pcpp::X509Decoder::decode(rawData.data(), rawData.size());
	PTF_ASSERT_NOT_NULL(decoder);
	PTF_ASSERT_EQUAL(decoder->getVersion(), 1);
	PTF_ASSERT_EQUAL(decoder->getSerialNumber(), "21c28a1bff4aa8400226fc73409b54bbc1f06c5f");

	std::cout << decoder->getNotBefore() << std::endl;
	std::cout << decoder->getNotAfter() << std::endl;
}
