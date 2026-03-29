#include <doctest.h>
#include <string_view>
#include <string>
#include <array>
#include <cstring>
#include <ostream>

#include "dlms_parser/axdr_parser.h"

using namespace dlms_parser;

TEST_CASE("AxdrParser Pattern Registry - Tokenization and Parsing") {
  AxdrParser parser;

  SUBCASE("Basic Tokens") {
    parser.register_pattern("test", "F,C,L", 10);
    REQUIRE(parser.patterns_size() == 1);
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
    REQUIRE(parser.patterns_size() == 1);
    const auto& pat = parser.patterns()[0];

    CHECK(pat.steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
    CHECK(pat.steps[1].type == AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
    CHECK(pat.steps[2].type == AxdrTokenType::EXPECT_TO_BE_LAST);
    CHECK(pat.steps[3].type == AxdrTokenType::END_OF_PATTERN);
  }

  SUBCASE("Garbage Tokens") {
    // Unrecognized tokens should be safely ignored
    parser.register_pattern("garbage", "F, INVALID_TOKEN, L", 10);
    REQUIRE(parser.patterns_size() == 1);
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

TEST_CASE("AxdrParser Pattern Registry - Comprehensive Token Mapping") {
  AxdrParser parser;

  // Test all primary token aliases
  parser.register_pattern("all_tokens", "TC,O,TO,TOW,A,TA,TS,TU,V,TV,TDTM,TSTR,DN,UP,TSU", 10);
  REQUIRE(parser.patterns_size() == 1);
  const auto& pat = parser.patterns()[0];

  size_t i = 0;
  // TC
  CHECK(pat.steps[i].type == AxdrTokenType::EXPECT_TYPE_EXACT);
  CHECK(pat.steps[i++].param_u8_a == DLMS_DATA_TYPE_UINT16);
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

TEST_CASE("AxdrParser Pattern Registry - Structure Expansion S(...)") {
  AxdrParser parser;

  SUBCASE("Simple structure") {
    parser.register_pattern("struct", "S(TO,TV)", 10);
    REQUIRE(parser.patterns_size() == 1);
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

TEST_CASE("AxdrParser Pattern Registry - Priority and Array Management") {
  AxdrParser parser;

  SUBCASE("Priority Sorting") {
    parser.register_pattern("low", "F", 50);
    parser.register_pattern("high", "F", 10);
    parser.register_pattern("med", "F", 30);

    REQUIRE(parser.patterns_size() == 3);
    // Lower number = higher priority, sorted to the front
    CHECK(std::string_view(parser.patterns()[0].name) == "high");
    CHECK(std::string_view(parser.patterns()[1].name) == "med");
    CHECK(std::string_view(parser.patterns()[2].name) == "low");
  }

  SUBCASE("Stable sorting for same priority") {
    parser.register_pattern("first", "F", 20);
    parser.register_pattern("second", "F", 20);
    parser.register_pattern("third", "F", 20);

    REQUIRE(parser.patterns_size() == 3);
    CHECK(std::string_view(parser.patterns()[0].name) == "first");
    CHECK(std::string_view(parser.patterns()[1].name) == "second");
    CHECK(std::string_view(parser.patterns()[2].name) == "third");
  }

  SUBCASE("Default OBIS assignment") {
    const uint8_t obis[] = {1, 0, 15, 8, 0, 255};
    parser.register_pattern("def_obis", "F", 10, obis);

    const auto& pat = parser.patterns()[0];
    CHECK(pat.has_default_obis == true);
    CHECK(std::memcmp(pat.default_obis, obis, 6) == 0);
  }

  SUBCASE("Default OBIS Flag Independence") {
    const uint8_t obis[] = {1, 0, 15, 8, 0, 255};
    parser.register_pattern("with_obis", "F", 10, obis);
    parser.register_pattern("without_obis", "L", 5); // Higher priority, inserted first

    // Pattern 0 (without_obis) should NOT have the default OBIS
    CHECK(parser.patterns()[0].has_default_obis == false);
    // Pattern 1 (with_obis) SHOULD have it
    CHECK(parser.patterns()[1].has_default_obis == true);
  }

  SUBCASE("Clear patterns") {
    parser.register_pattern("test", "F", 10);
    CHECK(parser.patterns_size() == 1);

    parser.clear_patterns();
    CHECK(parser.patterns_size() == 0);

    parser.register_pattern("test2", "L", 10);
    CHECK(parser.patterns_size() == 1);
    CHECK(std::string_view(parser.patterns()[0].name) == "test2");
  }
}

TEST_CASE("AxdrParser Pattern Registry - Limits and Edge Cases") {
  AxdrParser parser;

  SUBCASE("Max Patterns Limit (32)") {
    for (int i = 0; i < 40; i++) {
      parser.register_pattern("spam", "F", i);
    }
    // Hard limit is MAX_PATTERNS = 32
    CHECK(parser.patterns_size() == 32);
    // Since priority was 'i', 0-31 got inserted. The others gracefully overwrote the end
    // or were rejected, keeping the system stable without out-of-bounds writes.
  }

  SUBCASE("High Priority Insertion When Full") {
    // Fill the registry with priority 10
    for (int i = 0; i < 32; i++) {
      parser.register_pattern("filler", "V", 10);
    }
    CHECK(parser.patterns_size() == 32);

    // Insert a higher priority pattern (priority 1)
    parser.register_pattern("high_prio", "F", 1);

    // It should displace the last element and take the first position
    CHECK(parser.patterns_size() == 32);
    CHECK(std::string_view(parser.patterns()[0].name) == "high_prio");
    CHECK(parser.patterns()[0].steps[0].type == AxdrTokenType::EXPECT_TO_BE_FIRST);
  }

  SUBCASE("Max Tokens Limit (64)") {
    std::string huge_dsl = "";
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
    std::string many_steps_dsl = "";
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