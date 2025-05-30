#include "X509Decoder.h"
#include "Asn1Codec.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

namespace pcpp
{
    std::unique_ptr<X509Decoder> X509Decoder::decode(const uint8_t* data, size_t dataLen) {
        auto decoder = std::unique_ptr<X509Decoder>(new X509Decoder(Asn1Record::decode(data, dataLen)));
        decoder->parse();
        return decoder;
    }

    std::string X509Decoder::getSerialNumber() const
    {
        auto index = (getVersion() == 1) ? 0 : 1;
        return getTbsCertificate()->getSubRecords().at(index)->castAs<Asn1IntegerRecord>()->getValueAsString();
    }

    std::string X509Decoder::getNotBefore() const
    {
        auto index = (getVersion() == 1) ? 3 : 4;
        auto validityRecord = getTbsCertificate()->getSubRecords().at(index)->castAs<Asn1SequenceRecord>();
        return validityRecord->getSubRecords().at(0)->castAs<Asn1UtcTimeRecord>()->getValueAsString();
    }

    std::string X509Decoder::getNotAfter() const
    {
        auto index = (getVersion() == 1) ? 3 : 4;
        auto validityRecord = getTbsCertificate()->getSubRecords().at(index)->castAs<Asn1SequenceRecord>();
        return validityRecord->getSubRecords().at(1)->castAs<Asn1UtcTimeRecord>()->getValueAsString();
    }


    void X509Decoder::parse()
    {
        // TODO: calculate the version
        m_Version = 1;

        // size_t idx = 0;
        //
        // // Optional version (context-specific [0])
        // const Asn1Record* versionRec = tbsCertificate->getSubRecord(idx);
        // if (versionRec && versionRec->getTagClass() == ASN1_CONTEXT_SPECIFIC && versionRec->getTagNumber() == 0) {
        //     const Asn1Record* versionInt = versionRec->getSubRecord(0);
        //     version = versionInt->getValue()[0] + 1; // v1 = 0
        //     idx++;
        // } else {
        //     version = 1; // Default
        // }
        //
        // const Asn1Record* serialRec = tbsCertificate->getSubRecord(idx++);
        // serialNumber = asHexString(serialRec->getValue(), serialRec->getValueLength());
        //
        // const Asn1Record* sigAlg = tbsCertificate->getSubRecord(idx++);
        // signatureAlgorithm = asHexString(sigAlg->getValue(), sigAlg->getValueLength());
        //
        // issuer = parseName(tbsCertificate->getSubRecord(idx++));
        //
        // const Asn1Record* validity = tbsCertificate->getSubRecord(idx++);
        // notBefore = parseTime(validity->getSubRecord(0));
        // notAfter  = parseTime(validity->getSubRecord(1));
        //
        // subject = parseName(tbsCertificate->getSubRecord(idx++));
        //
        // const Asn1Record* subjectPublicKeyInfo = tbsCertificate->getSubRecord(idx++);
        // publicKeyAlgorithm = asHexString(subjectPublicKeyInfo->getSubRecord(0)->getValue(),
        //                                  subjectPublicKeyInfo->getSubRecord(0)->getValueLength());
    }

    // std::string X509Decoder::getIssuer() const { return issuer; }
    // std::string X509Decoder::getSubject() const { return subject; }
    // std::string X509Decoder::getNotBefore() const { return notBefore; }
    // std::string X509Decoder::getNotAfter() const { return notAfter; }
    // std::string X509Decoder::getSerialNumber() const { return serialNumber; }
    // std::string X509Decoder::getSignatureAlgorithm() const { return signatureAlgorithm; }
    // std::string X509Decoder::getPublicKeyAlgorithm() const { return publicKeyAlgorithm; }
    // int X509Decoder::getVersion() const { return version; }

    // std::string X509Decoder::parseName(const Asn1Record* nameSeq) {
    //     if (!nameSeq || !nameSeq->isConstructed()) return "";
    //     std::ostringstream oss;
    //
    //     for (size_t i = 0; i < nameSeq->getSubRecordsCount(); ++i) {
    //         const Asn1Record* rdnSet = nameSeq->getSubRecord(i);
    //         if (!rdnSet || !rdnSet->isConstructed()) continue;
    //
    //         for (size_t j = 0; j < rdnSet->getSubRecordsCount(); ++j) {
    //             const Asn1Record* attrTypeValue = rdnSet->getSubRecord(j);
    //             if (attrTypeValue && attrTypeValue->getSubRecordsCount() >= 2) {
    //                 const Asn1Record* oid = attrTypeValue->getSubRecord(0);
    //                 const Asn1Record* val = attrTypeValue->getSubRecord(1);
    //                 oss << oid->getValueAsString() << "=" << val->getValueAsString() << ", ";
    //             }
    //         }
    //     }
    //     std::string result = oss.str();
    //     if (!result.empty())
    //         result.pop_back(), result.pop_back(); // Remove trailing ", "
    //     return result;
    // }

    // std::string X509Decoder::parseTime(const Asn1Record* timeRecord) {
    //     if (!timeRecord) return "";
    //     return timeRecord->getValueAsString();
    // }
    //
    // std::string X509Decoder::asHexString(const uint8_t* data, size_t len) {
    //     std::ostringstream oss;
    //     for (size_t i = 0; i < len; ++i) {
    //         oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    //     }
    //     return oss.str();
    // }
}
