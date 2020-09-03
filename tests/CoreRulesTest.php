<?php
declare(strict_types=1);

namespace Meraki\Abnf;

use Meraki\TestSuite;
use ReflectionClass;

final class CoreRulesTest extends TestSuite
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