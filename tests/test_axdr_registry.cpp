#include <doctest.h>
#include <string_view>
#include <cstring>
#include <ostream>

#include "tests/log_fixture.h"
#include "dlms_parser/axdr_parser.h"
#include "dlms_parser/obis_id.h"

using namespace dlms_parser;

TEST_CASE_FIXTURE(LogFixture, "AxdrParser Pattern Registry - Tokenization and Parsing") {
  AxdrParser parser([](const auto&) {});

  SUBCASE("Basic Tokens") {
    parser.register_pattern("test", "F,C,L", 10);
    REQUIRE(parser.patterns().size() == 1);
    const auto& pat = parser.patterns()[0];

    CHECK(std::string_view(pat.name) == "test");
    CHECK(pat.priority == 10);
    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
    CHECK(pat.steps[1].type == AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
    CHECK(pat.steps[2].type == AxdrTokenType::EXPECT_TO_BE_LAST);
    CHECK(pat.steps[3].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Whitespace and Empty Tokens") {
    // Should gracefully trim spaces, tabs, newlines, and ignore empty tokens (,,)
    parser.register_pattern("ws", "  F \n, \t C ,,, L \r ", 10);
    REQUIRE(parser.patterns().size() == 1);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
    CHECK(pat.steps[1].type == AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
    CHECK(pat.steps[2].type == AxdrTokenType::EXPECT_TO_BE_LAST);
    CHECK(pat.steps[3].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Garbage Tokens") {
    // Unrecognized tokens should be safely ignored
    parser.register_pattern("garbage", "F, INVALID_TOKEN, L", 10);
    REQUIRE(parser.patterns().size() == 1);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
    CHECK(pat.steps[1].type == AxdrTokenType::EXPECT_TO_BE_LAST);
    CHECK(pat.steps[2].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Unbalanced Closing Parentheses") {
    // Because of a rogue ')', paren becomes negative, breaking comma splitting
    parser.register_pattern("unbalanced", "F, ), C", 10);
    const auto& pat = parser.patterns()[0];

    // "F" should parse. "), C" becomes a single garbage token and is ignored.
    // The "C" step will be completely missed.
    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
    CHECK(pat.steps[1].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Trailing Commas") {
    parser.register_pattern("trailing", "F,C,", 10);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
    CHECK(pat.steps[1].type == AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
    CHECK(pat.steps[2].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Case Sensitivity") {
    parser.register_pattern("lowercase", "f, c, l", 10);
    const auto& pat = parser.patterns()[0];

    // All tokens should be ignored
    CHECK(pat.steps[0].type == AxdrTokenType::END_OF_PATTERN);
  }
}

TEST_CASE_FIXTURE(LogFixture, "AxdrParser Pattern Registry - Comprehensive Token Mapping") {
  AxdrParser parser([](const auto&) {});

  // Test all primary token aliases
  parser.register_pattern("all_tokens", "SelfDesc,TC,O,TO,TOW,A,TA,TS,TU,V,TV,TDTM,TSTR,DN,UP,TSU", 10);
  REQUIRE(parser.patterns().size() == 1);
  const auto& pat = parser.patterns()[0];

  size_t i = 0;
  CHECK(pat.steps[i++].type == AxdrTokenType::SELF_DESC);
  // TC
  CHECK(pat.steps[i].type == AxdrTokenType::EXPECT_TYPE_EXACT);
  CHECK(pat.steps[i++].param_u8_a == static_cast<uint8_t>(DlmsDataType::UINT16));
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
  // O
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_OBIS6_UNTAGGED);
  // TO
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_OBIS6_TAGGED);
  // TOW
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_OBIS6_TAGGED_WRONG);
  // A
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_ATTR8_UNTAGGED);
  // TA
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_TYPE_U_I_8);
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_ATTR8_UNTAGGED);
  // TS
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_SCALER_TAGGED);
  // TU
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED);
  // V
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_VALUE_GENERIC);
  // TV (same as V)
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_VALUE_GENERIC);
  // TDTM
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_VALUE_DATE_TIME);
  // TSTR
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_VALUE_OCTET_STRING);
  // DN
  CHECK(pat.steps[i++].type == AxdrTokenType::GOING_DOWN);
  // UP
  CHECK(pat.steps[i++].type == AxdrTokenType::GOING_UP);
  // TSU (compound token)
  CHECK(pat.steps[i].type == AxdrTokenType::EXPECT_STRUCTURE_N);
  CHECK(pat.steps[i++].param_u8_a == 2);
  CHECK(pat.steps[i++].type == AxdrTokenType::GOING_DOWN);
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_SCALER_TAGGED);
  CHECK(pat.steps[i++].type == AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED);
  CHECK(pat.steps[i++].type == AxdrTokenType::GOING_UP);

  CHECK(pat.steps[i].type == AxdrTokenType::END_OF_PATTERN);
}

TEST_CASE_FIXTURE(LogFixture, "AxdrParser Pattern Registry - Structure Expansion S(...)") {
  AxdrParser parser([](const auto&) {});

  SUBCASE("Simple structure") {
    parser.register_pattern("struct", "S(TO,TV)", 10);
    REQUIRE(parser.patterns().size() == 1);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_STRUCTURE_N);
    CHECK(pat.steps[0].param_u8_a == 2);
    CHECK(pat.steps[1].type == AxdrTokenType::GOING_DOWN);
    CHECK(pat.steps[2].type == AxdrTokenType::EXPECT_OBIS6_TAGGED);
    CHECK(pat.steps[3].type == AxdrTokenType::EXPECT_VALUE_GENERIC);
    CHECK(pat.steps[4].type == AxdrTokenType::GOING_UP);
    CHECK(pat.steps[5].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Structure with whitespace") {
    parser.register_pattern("struct_ws", " S(  TO , \t TV  ) ", 10);
    const auto& pat = parser.patterns()[0];
    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_STRUCTURE_N);
    CHECK(pat.steps[0].param_u8_a == 2);
    CHECK(pat.steps[2].type == AxdrTokenType::EXPECT_OBIS6_TAGGED);
  }

  SUBCASE("Empty structure") {
    parser.register_pattern("empty_struct", "S()", 10);
    const auto& pat = parser.patterns()[0];
    // S() has no inner items, so `inner_count > 0` is false.
    // It should add zero steps.
    CHECK(pat.steps[0].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Empty inner structure tokens") {
    // Tests S(,,) to ensure it doesn't crash or create invalid steps
    parser.register_pattern("empty_inner", "S( , , )", 10);
    const auto& pat = parser.patterns()[0];

    // Because all inner tokens are empty, it should be treated the same as S()
    // and no steps should be added.
    CHECK(pat.steps[0].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Malformed structure parentheses") {
    // Missing closing parenthesis
    parser.register_pattern("malformed", "S(TO,TV", 10);
    const auto& pat = parser.patterns()[0];
    // Will fail to match S(...) and pass "S(TO,TV" as a garbage simple token (ignored)
    CHECK(pat.steps[0].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Nested structure limitation") {
    // The DSL doesn't do recursive parsing, so S(S(V)) will likely misinterpret the inner items.
    // We document this limitation: the inner "S(V)" is treated as a simple token, which is unrecognized.
    parser.register_pattern("nested", "S(S(V))", 10);
    const auto& pat = parser.patterns()[0];
    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_STRUCTURE_N);
    CHECK(pat.steps[0].param_u8_a == 1);
    CHECK(pat.steps[1].type == AxdrTokenType::GOING_DOWN);
    // The "S(V)" token was ignored
    CHECK(pat.steps[2].type == AxdrTokenType::GOING_UP);
  }
}

TEST_CASE_FIXTURE(LogFixture, "AxdrParser Pattern Registry - Priority and Array Management") {
  AxdrParser parser([](const auto&) {});

  SUBCASE("Priority Sorting") {
    parser.register_pattern("low", "F", 50);
    parser.register_pattern("high", "F", 10);
    parser.register_pattern("med", "F", 30);

    REQUIRE(parser.patterns().size() == 3);
    // Lower number = higher priority, sorted to the front
    CHECK(std::string_view(parser.patterns()[0].name) == "high");
    CHECK(std::string_view(parser.patterns()[1].name) == "med");
    CHECK(std::string_view(parser.patterns()[2].name) == "low");
  }

  SUBCASE("Stable sorting for same priority") {
    parser.register_pattern("first", "F", 20);
    parser.register_pattern("second", "F", 20);
    parser.register_pattern("third", "F", 20);

    REQUIRE(parser.patterns().size() == 3);
    CHECK(std::string_view(parser.patterns()[0].name) == "first");
    CHECK(std::string_view(parser.patterns()[1].name) == "second");
    CHECK(std::string_view(parser.patterns()[2].name) == "third");
  }

  SUBCASE("Default OBIS assignment") {
    constexpr ObisId obis(1, 0, 15, 8, 0, 255);
    parser.register_pattern("def_obis", "F", 10, obis);

    const auto& pat = parser.patterns()[0];
    CHECK(pat.default_obis == obis);
  }

  SUBCASE("Default OBIS Flag Independence") {
    constexpr ObisId obis(1, 0, 15, 8, 0, 255);
    parser.register_pattern("with_obis", "F", 10, obis);
    parser.register_pattern("without_obis", "L", 5); // Higher priority, inserted first

    // Pattern 0 (without_obis) should NOT have the default OBIS
    CHECK(parser.patterns()[0].default_obis.empty() == true);
    // Pattern 1 (with_obis) SHOULD have it
    CHECK(parser.patterns()[1].default_obis == obis);
  }

  SUBCASE("Clear patterns") {
    parser.register_pattern("test", "F", 10);
    CHECK(parser.patterns().size() == 1);

    parser.clear_patterns();
    CHECK(parser.patterns().size() == 0);

    parser.register_pattern("test2", "L", 10);
    CHECK(parser.patterns().size() == 1);
    CHECK(std::string_view(parser.patterns()[0].name) == "test2");
  }
}

TEST_CASE_FIXTURE(LogFixture, "AxdrParser Pattern Registry - Limits and Edge Cases") {
  AxdrParser parser([](const auto&) {});

  SUBCASE("Max Patterns Limit (32)") {
    for (int i = 0; i < 40; i++) {
      parser.register_pattern("spam", "F", i);
    }
    // Hard limit is MAX_PATTERNS = 32
    CHECK(parser.patterns().size() == 32);
    // Since priority was 'i', 0-31 got inserted. The others gracefully overwrote the end
    // or were rejected, keeping the system stable without out-of-bounds writes.
  }

  SUBCASE("High Priority Insertion When Full") {
    // Fill the registry with priority 10
    for (int i = 0; i < 32; i++) {
      parser.register_pattern("filler", "V", 10);
    }
    CHECK(parser.patterns().size() == 32);

    // Insert a higher priority pattern (priority 1)
    parser.register_pattern("high_prio", "F", 1);

    // It should displace the last element and take the first position
    CHECK(parser.patterns().size() == 32);
    CHECK(std::string_view(parser.patterns()[0].name) == "high_prio");
    CHECK(parser.patterns()[0].steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
  }

  SUBCASE("Max Tokens Limit (64)") {
    std::string huge_dsl;
    for (int i = 0; i < 70; i++) {
      huge_dsl += "V,";
    }
    parser.register_pattern("huge", huge_dsl.c_str(), 10);
    const auto& pat = parser.patterns()[0];

    // The parser only extracts the first 64 tokens. Note that each "V" adds 1 step.
    // However, steps are ALSO limited to 32. So we check step_count capping next.
    // But this test ensures no crash parsing the string itself.
    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_VALUE_GENERIC);
  }

  SUBCASE("Max Steps Limit (32)") {
    std::string many_steps_dsl;
    for (int i = 0; i < 50; i++) {
      many_steps_dsl += "V,";
    }
    parser.register_pattern("many_steps", many_steps_dsl.c_str(), 10);
    const auto& pat = parser.patterns()[0];

    // Should successfully cap at 32 steps.
    // Step 31 is the last written step. The 32nd byte doesn't exist to be checked safely
    // without knowing implementation bounds, but we can verify it doesn't crash
    // and correctly processes up to the limit.
    CHECK(pat.steps[31].type == AxdrTokenType::EXPECT_VALUE_GENERIC);
  }

  SUBCASE("Max Inner Tokens Limit (16)") {
    // S(...) can hold at most 16 inner tokens
    std::string huge_struct = "S(";
    for (int i = 0; i < 20; i++) {
      huge_struct += "V";
      if (i < 19) huge_struct += ",";
    }
    huge_struct += ")";

    parser.register_pattern("huge_struct", huge_struct.c_str(), 10);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_STRUCTURE_N);
    // It should have capped the structure size param to 16
    CHECK(pat.steps[0].param_u8_a == 16);
  }
}

namespace {

// "ZPA3HAN00200" as hex, for the ~hexbytes guard syntax.
constexpr const char* kZpaHex = "5A50413348414E3030323030";

bool prefix_equals(const FlatFieldSpec& field, const std::string_view ascii) {
  return field.expected_prefix_len == ascii.size() &&
         std::ranges::equal(std::span(field.expected_prefix).first(field.expected_prefix_len), ascii);
}

}

TEST_CASE_FIXTURE(LogFixture, "AxdrParser Pattern Registry - FLAT_POSITIONAL from text") {
  AxdrParser parser([](const auto&) {});

  SUBCASE("Valid field list with a hex literal guard") {
    const std::string dsl = std::string("0.0.96.1.4.255~") + kZpaHex + ", 0.0.1.0.0.255, 0.0.96.1.1.255";
    const bool ok = parser.register_flat_positional_pattern("flat", 10, dsl.c_str());
    REQUIRE(ok);
    REQUIRE(parser.patterns().size() == 1);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::FLAT_POSITIONAL);
    REQUIRE(pat.flat_field_count == 3);
    CHECK(pat.flat_fields[0].obis == ObisId(0, 0, 96, 1, 4, 255));
    CHECK(prefix_equals(pat.flat_fields[0], "ZPA3HAN00200"));
    CHECK(pat.flat_fields[1].obis == ObisId(0, 0, 1, 0, 0, 255));
    CHECK(pat.flat_fields[1].expected_prefix_len == 0);
    CHECK(pat.flat_fields[2].obis == ObisId(0, 0, 96, 1, 1, 255));
  }

  SUBCASE("Whitespace around commas and '~' is tolerated") {
    const std::string dsl = std::string("  0.0.96.1.4.255 ~ ") + kZpaHex + "  ,  0.0.1.0.0.255  ";
    const bool ok = parser.register_flat_positional_pattern("flat", 10, dsl.c_str());
    REQUIRE(ok);
    const auto& pat = parser.patterns()[0];
    REQUIRE(pat.flat_field_count == 2);
    CHECK(prefix_equals(pat.flat_fields[0], "ZPA3HAN00200"));
  }

  SUBCASE("Malformed input rejects the whole registration") {
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.0.0.0.0~0000000000000000000000000000000000")); // one byte too long
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4=bad, 0.0.1.0.0.255"));
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4.999.255")); // too long OBIS code
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4.255~ZZ"));  // matcher not hex
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4.255~5A5")); // matcher odd length
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4.255~")); // empty matcher
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4.255,")); // trailing empty field
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, ",0.0.96.1.4.255,")); // leading empty field
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, "0.0.96.1.4.255,,0.0.1.0.0.255")); // empty field in the middle
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, ""));
    CHECK_FALSE(parser.register_flat_positional_pattern("flat", 10, nullptr));
    CHECK(parser.patterns().empty());
  }
}
