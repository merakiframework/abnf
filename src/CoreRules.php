<?php
declare(strict_types=1);

namespace Meraki\Abnf;

use Generator;

// https://tools.ietf.org/html/rfc5234
abstract class CoreRules
{
	// %x41-5A / %x61-7A ; A-Z / a-z
	const ALPHA = [
		"\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48","\x49","\x4A","\x4B","\x4C",
		"\x4D","\x4E","\x4F","\x50","\x51","\x52","\x53","\x54","\x55","\x56","\x57","\x58",
		"\x59","\x5A","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6A",
		"\x6B","\x6C","\x6D","\x6E","\x6F","\x70","\x71","\x72","\x73","\x74","\x75","\x76",
		"\x77","\x78","\x79","\x7A"
	];

	// "0" / "1"
	const BIT = ["\x30","\x31"];

	// %x01-7F ; Any 7-bit US-ASCII character excluding NUL
	const CHAR = [
		"\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0A","\x0B","\x0C",
		"\x0D","\x0E","\x0F","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18",
		"\x19","\x1A","\x1B","\x1C","\x1D","\x1E","\x1F","\x20","\x21","\x22","\x23","\x24",
		"\x25","\x26","\x27","\x28","\x29","\x2A","\x2B","\x2C","\x2D","\x2E","\x2F","\x30",
		"\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3A","\x3B","\x3C",
		"\x3D","\x3E","\x3F","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48",
		"\x49","\x4A","\x4B","\x4C","\x4D","\x4E","\x4F","\x50","\x51","\x52","\x53","\x54",
		"\x55","\x56","\x57","\x58","\x59","\x5A","\x5B","\x5C","\x5D","\x5E","\x5F","\x60",
		"\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6A","\x6B","\x6C",
		"\x6D","\x6E","\x6F","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77","\x78",
		"\x79","\x7A","\x7B","\x7C","\x7D","\x7E","\x7F"
	];

	// %x0D ; carriage return
	const CR = ["\x0D"];

	// CR LF ; Internet standard newline
	const CRLF = ["\x0d\x0A"];

	// %x00-1F / %x7F ; controls
	const CTL = [
		"\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0A","\x0B",
		"\x0C","\x0D","\x0E","\x0F","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17",
		"\x18","\x19","\x1A","\x1B","\x1C","\x1D","\x1E","\x1F","\x7F"
	];

	// %x30-39 ; 0-9
	const DIGIT = ["\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39"];

	// %x22 ; " (Double Quote)
	const DQUOTE = ["\x22"];

	// DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
	const HEXDIG = [
		"\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x41","\x42",
		"\x43","\x44","\x45","\x46"
	];

	// %x09 ; horizontal tab
	const HTAB = ["\x09"];

	// %x0A ; linefeed
	const LF = ["\x0A"];

	// *(WSP / CRLF WSP)
	const LWSP = [
		"\x20\x09",	// WSP
		"\x0d\x0A\x20\x09"	// CRLF WSP
	];

	// %x00-FF ; 8 bits of data
	const OCTET = [
		"\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0A","\x0B",
		"\x0C","\x0D","\x0E","\x0F","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17",
		"\x18","\x19","\x1A","\x1B","\x1C","\x1D","\x1E","\x1F","\x20","\x21","\x22","\x23",
		"\x24","\x25","\x26","\x27","\x28","\x29","\x2A","\x2B","\x2C","\x2D","\x2E","\x2F",
		"\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3A","\x3B",
		"\x3C","\x3D","\x3E","\x3F","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47",
		"\x48","\x49","\x4A","\x4B","\x4C","\x4D","\x4E","\x4F","\x50","\x51","\x52","\x53",
		"\x54","\x55","\x56","\x57","\x58","\x59","\x5A","\x5B","\x5C","\x5D","\x5E","\x5F",
		"\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6A","\x6B",
		"\x6C","\x6D","\x6E","\x6F","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77",
		"\x78","\x79","\x7A","\x7B","\x7C","\x7D","\x7E","\x7F","\x80","\x81","\x82","\x83",
		"\x84","\x85","\x86","\x87","\x88","\x89","\x8A","\x8B","\x8C","\x8D","\x8E","\x8F",
		"\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9A","\x9B",
		"\x9C","\x9D","\x9E","\x9F","\xA0","\xA1","\xA2","\xA3","\xA4","\xA5","\xA6","\xA7",
		"\xA8","\xA9","\xAA","\xAB","\xAC","\xAD","\xAE","\xAF","\xB0","\xB1","\xB2","\xB3",
		"\xB4","\xB5","\xB6","\xB7","\xB8","\xB9","\xBA","\xBB","\xBC","\xBD","\xBE","\xBF",
		"\xC0","\xC1","\xC2","\xC3","\xC4","\xC5","\xC6","\xC7","\xC8","\xC9","\xCA","\xCB",
		"\xCC","\xCD","\xCE","\xCF","\xD0","\xD1","\xD2","\xD3","\xD4","\xD5","\xD6","\xD7",
		"\xD8","\xD9","\xDA","\xDB","\xDC","\xDD","\xDE","\xDF","\xE0","\xE1","\xE2","\xE3",
		"\xE4","\xE5","\xE6","\xE7","\xE8","\xE9","\xEA","\xEB","\xEC","\xED","\xEE","\xEF",
		"\xF0","\xF1","\xF2","\xF3","\xF4","\xF5","\xF6","\xF7","\xF8","\xF9","\xFA","\xFB",
		"\xFC","\xFD","\xFE","\xFF"
	];

	// %x20
	const SP = ["\x20"];

	// %x21-7E ; visible (printing) characters
	const VCHAR = [
		"\x21","\x22","\x23","\x24","\x25","\x26","\x27","\x28","\x29","\x2A","\x2B","\x2C",
		"\x2D","\x2E","\x2F","\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38",
		"\x39","\x3A","\x3B","\x3C","\x3D","\x3E","\x3F","\x40","\x41","\x42","\x43","\x44",
		"\x45","\x46","\x47","\x48","\x49","\x4A","\x4B","\x4C","\x4D","\x4E","\x4F","\x50",
		"\x51","\x52","\x53","\x54","\x55","\x56","\x57","\x58","\x59","\x5A","\x5B","\x5C",
		"\x5D","\x5E","\x5F","\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68",
		"\x69","\x6A","\x6B","\x6C","\x6D","\x6E","\x6F","\x70","\x71","\x72","\x73","\x74",
		"\x75","\x76","\x77","\x78","\x79","\x7A","\x7B","\x7C","\x7D","\x7E"
	];

	// SP / HTAB ; white space
	const WSP = ["\x20", "\x09"];

	/**
	 * Generate each individual character from the ABNF rules selected.
	 */
	public static function generateCharactersFromRules(array ...$rules): Generator
	{
	    $generated = [];

		foreach ($rules as $rule) {
			foreach ($rule as $char) {

				// Don't allow same character to be generated more than once.
			    if (!in_array($char, $generated, true)) {
				    yield $char;
			    }
			    
				$generated[] = $char;
			}
		}
	}
	
	/**
	 * Generate each individual character not contained in the ABNF rules passed in.
	 */
	public static function generateCharactersNotInRules(array ...$rules): Generator
	{
	    for ($i = 0; $i < 256; $i++) {
	        foreach(self::generateCharactersFromRules(...$rules) as $character) {
    	        if ($i === ord($character)) {
                    continue 2;	// skip yielding character
                }
    	    }
    	    
    	    yield chr($i);
        }
	}
}