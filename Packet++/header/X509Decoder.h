#pragma once

#include <string>
#include <vector>
#include <memory>
#include "Asn1Codec.h"

namespace pcpp
{
	class X509Decoder {
	public:
		static std::unique_ptr<X509Decoder> decode(const uint8_t* data, size_t dataLen);

		// Getters for common X.509 fields
		int getVersion() const { return m_Version; }
		std::string getSerialNumber() const;
		// std::string getIssuer() const;
		// std::string getSubject() const;
		std::string getNotBefore() const;
		std::string getNotAfter() const;
		// std::string getPublicKeyAlgorithm() const;
		// std::string getSignatureAlgorithm() const;

	private:
		explicit X509Decoder(std::unique_ptr<Asn1Record> root) : m_Root(std::move(root)) {};

		Asn1SequenceRecord* X509Decoder::getRoot() const
		{
			return m_Root->castAs<Asn1SequenceRecord>();
		}

		Asn1SequenceRecord* X509Decoder::getTbsCertificate() const
		{
			return getRoot()->getSubRecords().at(0)->castAs<Asn1SequenceRecord>();
		}

		// Parsed fields
		// int version = 0;
		// std::string serialNumber;
		// std::string issuer;
		// std::string subject;
		// std::string notBefore;
		// std::string notAfter;
		// std::string publicKeyAlgorithm;
		// std::string signatureAlgorithm;

		void parse();
		// std::string parseName(const pcpp::Asn1Record* nameSeq);
		// std::string parseTime(const pcpp::Asn1Record* timeRecord);
		// std::string asHexString(const uint8_t* data, size_t len);

		std::unique_ptr<Asn1Record> m_Root;
		int m_Version = -1;

	};
}