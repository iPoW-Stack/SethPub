#include <gtest/gtest.h>

#include <string>

#include "common/country_code.h"

namespace shardora {
namespace common {
namespace test {

TEST(CountryCodeMapsBranches, Alpha2ToCodeMatchesEnum) {
    EXPECT_EQ(global_country_map.at("US"), static_cast<uint8_t>(US));
    EXPECT_EQ(global_country_map.at("CN"), static_cast<uint8_t>(CN));
    EXPECT_EQ(global_country_map.at("DE"), static_cast<uint8_t>(DE));
}

TEST(CountryCodeMapsBranches, CodeToAlpha2RoundTrip) {
    EXPECT_EQ(global_code_to_country_map.at(static_cast<uint8_t>(US)), "US");
    EXPECT_EQ(global_code_to_country_map.at(static_cast<uint8_t>(UK)), "UK");
}

TEST(CountryCodeMapsBranches, EnglishMapHasEntriesForMajorCountries) {
    EXPECT_EQ(global_code_to_country_english_map.at(static_cast<uint8_t>(CN)), "China");
    EXPECT_EQ(global_code_to_country_english_map.at(static_cast<uint8_t>(FR)), "France");
}

TEST(CountryCodeMapsBranches, UnknownAlpha2ThrowsOrMissing) {
    EXPECT_EQ(global_country_map.find("ZZ"), global_country_map.end());
}

TEST(CountryCodeMapsBranches, Alpha2CodeRoundTripGermany) {
    const uint8_t code = global_country_map.at("DE");
    EXPECT_EQ(global_code_to_country_map.at(code), "DE");
}

TEST(CountryCodeMapsBranches, EnglishNameForGermany) {
    const uint8_t code = global_country_map.at("DE");
    EXPECT_FALSE(global_code_to_country_english_map.at(code).empty());
}

}  // namespace test
}  // namespace common
}  // namespace shardora
