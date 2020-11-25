<?php
declare(strict_types=1);

namespace Meraki\Abnf;

use Meraki\TestSuite\TestCase;
use ReflectionClass;

final class CoreRulesTest extends TestCase
{
	/**
	 * @test
	 * @dataProvider coreRules
	 */
	public function core_rules_are_defined(string $coreRule): void
	{
		$coreRules = new ReflectionClass(CoreRules::class);

		$isDefined = $coreRules->hasConstant($coreRule);

		$this->assertTrue($isDefined);
	}

	/**
	 * @test
	 */
	public function alpha_rule_has_correct_characters(): void
	{
		// %x41-5A / %x61-7A  ; A-Z / a-z
		$expectedCharacters = array_merge(range("\x41", "\x5A"), range("\x61", "\x7A"));

		$actualCharacters = CoreRules::ALPHA;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function bit_rule_has_correct_characters(): void
	{
		// "0" / "1"
		$expectedCharacters = ["0", "1"];

		$actualCharacters = CoreRules::BIT;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function char_rule_has_correct_characters(): void
	{
		// %x01-7F	; any 7-bit us-ascii character, excluding NUL
		$expectedCharacters = range("\x01", "\x7F");

		$actualCharacters = CoreRules::CHAR;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function cr_rule_has_correct_characters(): void
	{
		// %x0D	 ; carriage return
		$expectedCharacters = ["\x0D"];

		$actualCharacters = CoreRules::CR;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function crlf_rule_has_correct_characters(): void
	{
		// CR LF  ; Internet standard newline
		$expectedCharacters = ["\x0D\x0A"];

		$actualCharacters = CoreRules::CRLF;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function ctl_rule_has_correct_characters(): void
	{
		// %x00-1F / %x7F  ; controls
		$expectedCharacters = array_merge(range("\x00", "\x1F"), ["\x7F"]);

		$actualCharacters = CoreRules::CTL;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function digit_rule_has_correct_characters(): void
	{
		// %x30-39	; 0-9
		$expectedCharacters = range("\x30", "\x39");

		$actualCharacters = CoreRules::DIGIT;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function dquote_rule_has_correct_characters(): void
	{
		// %x22  ; " (Double Quote)
		$expectedCharacters = ['"'];

		$actualCharacters = CoreRules::DQUOTE;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function hexdig_rule_has_correct_characters(): void
	{
		// DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
		$expectedCharacters = array_merge(range("\x30", "\x39"), ["A", "B", "C", "D", "E", "F"]);

		$actualCharacters = CoreRules::HEXDIG;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function htab_rule_has_correct_characters(): void
	{
		// %x09  ; horizontal tab
		$expectedCharacters = ["\x09"];

		$actualCharacters = CoreRules::HTAB;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function lf_rule_has_correct_characters(): void
	{
		// %x0A  ; linefeed
		$expectedCharacters = ["\x0A"];

		$actualCharacters = CoreRules::LF;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function lwsp_rule_has_correct_characters(): void
	{
		// *(WSP / CRLF WSP)
		$expectedCharacters = ["", "\x20", "\x09", "\x0D\x0A\x20", "\x0D\x0A\x09"];

		$actualCharacters = CoreRules::LWSP;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function octet_rule_has_correct_characters(): void
	{
		// %x00-FF  ; 8 bits of data
		$expectedCharacters = range("\x00", "\xFF");

		$actualCharacters = CoreRules::OCTET;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function sp_rule_has_correct_characters(): void
	{
		// %x20
		$expectedCharacters = ["\x20"];

		$actualCharacters = CoreRules::SP;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function vchar_rule_has_correct_characters(): void
	{
		// %x21-7E  ; visible (printing) characters
		$expectedCharacters = range("\x21", "\x7E");

		$actualCharacters = CoreRules::VCHAR;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	/**
	 * @test
	 */
	public function wsp_rule_has_correct_characters(): void
	{
		// SP / HTAB  ; white space
		$expectedCharacters = ["\x20", "\x09"];

		$actualCharacters = CoreRules::WSP;

		$this->assertEquals($expectedCharacters, $actualCharacters);
	}

	// https://tools.ietf.org/html/rfc5234#appendix-B
	public function coreRules(): array
	{
		return [
			'ALPHA' => ['ALPHA'],
			'BIT' => ['BIT'],
			'CHAR' => ['CHAR'],
			'CR' => ['CR'],
			'CRLF' => ['CRLF'],
			'CTL' => ['CTL'],
			'DIGIT' => ['DIGIT'],
			'DQUOTE' => ['DQUOTE'],
			'HEXDIG' => ['HEXDIG'],
			'HTAB' => ['HTAB'],
			'LF' => ['LF'],
			'LWSP' => ['LWSP'],
			'OCTET' => ['OCTET'],
			'SP' => ['SP'],
			'VCHAR' => ['VCHAR'],
			'WSP' => ['WSP']
		];
	}
}
