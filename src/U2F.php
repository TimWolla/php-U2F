<?php namespace TimWolla\U2F;
/**
 * Copyright (c) 2016 Tim Düsterhus
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * Implements the Universal Second Factor specification
 * as published by the FIDO alliance.
 */
class U2F {
	const VERSION = 'U2F_V2';

	/**
	 * The appId to use for all messages.
	 *
	 * @var   string
	 */
	protected $appId;

	/**
	 * The OpenSSL binary to use for signature validation.
	 *
	 * @var   string|null
	 */
	protected $opensslBinary = null;

	public function __construct($appId, $opensslBinary = null) {
		$this->appId = $appId;
		$this->opensslBinary = $opensslBinary;
	}

	/**
	 * This method generates the RegisterRequest dictionary as
	 * specified in section
	 *   4.1.1 Dictionary RegisterRequest Members
	 * of the FIDO U2F Javascript API specification.
	 *
	 * @return   string[]
	 */
	public function generateRegisterRequest() {
		$s = false;
		$challenge = openssl_random_pseudo_bytes(32, $s);
		if (!$s) throw new \RuntimeException('Unable to generate a random challenge');

		// Perform web safe base 64 encoding of the challenge.
		$challenge = $this->base64url_encode($challenge);
		// Strip base 64 padding.
		$challenge = rtrim($challenge, '=');

		return array(
			'version'   => self::VERSION,
			'challenge' => $challenge,
			'appId'     => $this->appId,
		);
	}

	/**
	 * This method decodes and verifies the RegisterResponse
	 * dictionary as specified in section
	 *   4.1.2 Dictionary RegisterResponse Members
	 * of the FIDO U2F Javascript API specification
	 * and section
	 *   4.3 Registration Response Message: Success
	 * of the FIDO U2F Raw Message Formats specification.
	 *
	 * It returns an opaque structure to be stored and
	 * passed into generateSignRequest() and
	 * verifySignResponse().
	 * It throws, if it cannot verify the passed data.
	 *
	 * @param    string[]   $request    The request to verify. This must be the structure returned by generateRegisterRequest().
	 * @param    string[]   $response   The response given by the U2F device.
	 * @param    mixed[]    &$optReturn Auxiliary return values (raw data, for debug purposes).
	 * @return   array
	 * @throws   \UnexpectedValueException if the response is invalid
	 */
	public function verifyRegisterResponse(array $request, array $response, &$optReturn = array()) {
		if (!isset($response['clientData']) || !isset($response['registrationData'])) {
			 throw new \UnexpectedValueException('Invalid response');
		}

		$clientData = json_decode($this->base64url_decode($response['clientData']), true);

		// Check whether the clientData could be parsed properly
		if (json_last_error() !== JSON_ERROR_NONE) throw new \UnexpectedValueException('Invalid clientData');

		$registrationData = $this->base64url_decode($response['registrationData']);
	
		// Verify typ inside clientData.
		if ($clientData['typ'] !== 'navigator.id.finishEnrollment') throw new \UnexpectedValueException('Invalid clientData');

		// Verify challenge inside clientData.
		if ($this->base64url_decode($clientData['challenge']) !== $this->base64url_decode($request['challenge'])) throw new \UnexpectedValueException('Invalid clientData');

		// TODO: Validate origin?

		$offset   = 0;
		$reserved =     mb_substr($registrationData, $offset, $read = 1,  '8bit');
		$offset  += $read;
		$pubKey   =     mb_substr($registrationData, $offset, $read = 65, '8bit');
		$offset  += $read;
		$L        = ord(mb_substr($registrationData, $offset, $read = 1 , '8bit'));
		$offset  += $read;
		$handle   =     mb_substr($registrationData, $offset, $read = $L, '8bit');
		$offset  += $read;

		$parseCert = function () use (&$offset, $registrationData) {
			// Now follows a X.509 certificate in DER format.
			// see RFC 5280, Section 4.1
			// X.680 refers to the document published at: https://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
			// X.690 refers to the document published at: https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

			$certOffset = $offset;
			// Tag number of SEQUENCE is 16 (X.680, section 8.4)
			// The encoding of SEQUENCE is constructed (X.690, section 8.9.1)
			// Thus the identifier octet must be the value 16 with bit 6 set to 1 (X.690, section 8.1.2)
			if (ord($registrationData[$certOffset++]) !== (16 | (1 << 5))) throw new \UnexpectedValueException('Invalid registrationData');

			// DER employs the definite form of length encoding (X.690, section 10.1)
			// Check whether we are dealing with a long form length (X.690, section 8.1.3.5)
			$length = 0;
			if (ord($registrationData[$certOffset]) & (1 << 7)) {
				$lengthBytes = ord($registrationData[$certOffset++]) & ~(1 << 7);
				for ($i = 0; $i < $lengthBytes; $i++) $length = ($length * (1 << 8)) + ord($registrationData[$certOffset++]);
			}
			else {
				$length = ord($registrationData[$certOffset++]);
			}

			$length += ($certOffset - $offset);

			$cert = mb_substr($registrationData, $offset, $length, '8bit');
			if (mb_strlen($cert, '8bit') !== $length) throw new \UnexpectedValueException('Invalid registrationData');
			$offset += $length;

			return $cert;
		};

		if ($reserved !== "\x05")              throw new \UnexpectedValueException('Invalid registrationData');
		if (mb_strlen($pubKey, '8bit') !== 65) throw new \UnexpectedValueException('Invalid registrationData');
		if (mb_strlen($handle, '8bit') !== $L) throw new \UnexpectedValueException('Invalid registrationData');

		$cert = $parseCert();
		$signature = mb_substr($registrationData, $offset, null, '8bit');

		$toSign  = "\x00";
		$toSign .= hash('sha256', $request['appId'], true);
		// Note: The specification talks about 'challenge' here, while referring to the ClientData struct
		//       which contains a key called 'challenge'. We need to hash the whole struct!
		$toSign .= hash('sha256', $this->base64url_decode($response['clientData']), true);
		$toSign .= $handle;
		$toSign .= $pubKey;

		$certAsPem = "-----BEGIN CERTIFICATE-----\r\n".chunk_split(base64_encode($cert), 80)."-----END CERTIFICATE-----";

		if (!$this->openssl_verify_by_cert($toSign, $signature, $certAsPem)) throw new \UnexpectedValueException('Invalid registrationData');

		$optReturn = array(
			'clientData' => $clientData,
			'registrationData' => array(
				'reserved'  => $reserved,
				'pubKey'    => $pubKey,
				'handle'    => $handle,
				'cert'      => $cert,
				'certAsPem' => $certAsPem,
				'signature' => $signature
			)
		);

		return array(
			'version'   => self::VERSION,
			'pubKey'    => $this->curvePointToDer($pubKey),
			'keyHandle' => $handle,
			'counter'   => 0
		);
	}

	/**
	 * This method generates the parameters for the sign request as
	 * specified in section
	 *   3.2.1 Methods
	 * of the FIDO U2F Javascript API specification.
	 *
	 * @param    string[][]   $keys  An array of keys as returned by verifyRegisterResponse().
	 * @return   string[]
	 */
	public function generateSignRequest(array $keys) {
		$s = false;
		$challenge = openssl_random_pseudo_bytes(32, $s);
		if (!$s) throw new \RuntimeException('Unable to generate a random challenge');

		// Perform web safe base 64 encoding of the challenge.
		$challenge = $this->base64url_encode($challenge);
		// Strip base 64 padding.
		$challenge = rtrim($challenge, '=');

		$keys = array_map(function ($item) {
			return array(
				'version'   => $item['version'],
				'keyHandle' => rtrim($this->base64url_encode($item['keyHandle']), '=')
			);
		}, $keys);

		return array(
			'challenge'      => $challenge,
			'appId'          => $this->appId,
			'registeredKeys' => $keys
		);
	}

	/**
	 * This method decodes and verifies the SignResponse
	 * dictionary as specified in section
	 *   5.2.2 Dictionary SignResponse Members
	 * of the FIDO U2F Javascript API specification
	 * and section
	 *   5.4 Authentication Response Message: Success
	 * of the FIDO U2F Raw Message Formats specification.
	 *
	 * It returns an modified $keys array. The caller must
	 * replace the stored keys with the keys in this array.
	 * It throws, if it cannot verify the passed data.
	 *
	 * @param    string[]   $request    The request to verify. This must be the structure returned by generateSignRequest().
	 * @param    mixed[][]  $keys       An array of keys as returned by verifyRegisterResponse().
	 * @param    string[]   $response   The response given by the U2F device.
	 * @param    mixed[]   &$optReturn  Auxiliary return values (raw data, for debug purposes).
	 * @return   mixed[][]
	 * @throws   \UnexpectedValueException if the response is invalid
	 */
	public function verifySignResponse(array $request, array $keys, array $response, &$optReturn = array()) {
		if (!isset($response['clientData']) || !isset($response['signatureData'])) {
			 throw new \UnexpectedValueException('Invalid response');
		}

		$clientData = json_decode($this->base64url_decode($response['clientData']), true);

		// Check whether the clientData could be parsed properly
		if (json_last_error() !== JSON_ERROR_NONE) throw new \UnexpectedValueException('Invalid clientData');

		$signatureData = $this->base64url_decode($response['signatureData']);
	
		// Verify typ inside clientData.
		if ($clientData['typ'] !== 'navigator.id.getAssertion') throw new \UnexpectedValueException('Invalid clientData');

		// Verify challenge inside clientData.
		if ($this->base64url_decode($clientData['challenge']) !== $this->base64url_decode($request['challenge'])) throw new \UnexpectedValueException('Invalid clientData');

		// TODO: Validate origin?

		$offset = 0;
		$presence  =          ord(mb_substr($signatureData, $offset, $read = 1, '8bit'));
		$offset   += $read;
		$counter   = unpack('Nc', mb_substr($signatureData, $offset, $read = 4, '8bit'))['c'];
		$offset   += $read;
		$signature =              mb_substr($signatureData, $offset, null,      '8bit');

		$keyHandle = $this->base64url_decode($response['keyHandle']);

		// Presence Bit
		if (!($presence & 0b00000001)) throw new \UnexpectedValueException('Invalid signatureData');
		// Reserved Bits
		if (  $presence & 0b11111110 ) throw new \UnexpectedValueException('Invalid signatureData');

		foreach ($keys as &$key) {
			if ($keyHandle !== $key['keyHandle']) continue;

			$toSign  = hash('sha256', $request['appId'], true);
			$toSign .= chr($presence);
			$toSign .= pack('N', $counter);
			// Note: The specification talks about 'challenge' here, while referring to the ClientData struct
			//       which contains a key called 'challenge'. We need to hash the whole struct!
			$toSign .= hash('sha256', $this->base64url_decode($response['clientData']), true);

			$keyAsPem = "-----BEGIN PUBLIC KEY-----\r\n".chunk_split(base64_encode($key['pubKey']), 80)."-----END PUBLIC KEY-----";

			if (!$this->openssl_verify_by_key($toSign, $signature, $keyAsPem)) throw new \UnexpectedValueException('Invalid signatureData');

			if ($counter <= $key['counter']) throw new \UnexpectedValueException('Counter jumped back');
		
			$key['counter'] = $counter;

			$optReturn = array(
				'clientData' => $clientData,
				'signatureData' => array(
					'presence'  => $presence,
					'counter'   => $counter,
					'signature' => $signature
				)
			);

			return $keys;
		}

		throw new \UnexpectedValueException('Cannot find key');
	}

	/**
	 * Converts the given x,y-representation of an uncompressed curve point on the P-256 NIST elliptic curve
	 * as given in section
	 *   4.3 Registration Response Message: Success
	 * of the FIDO U2F Raw Message Formats specification.
	 * into it's DER format.
	 */
	protected function curvePointToDer($point) {
		// The syntax of a ECC public key is defined
		// in RFC 5480, section 2. Subject Public Key Information Fields

		// X.680 refers to the document published at: https://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
		// X.690 refers to the document published at: https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

		$encodeSubIdentifier = function ($id) {
			$result = chr($id % 0x80);
			$id = floor($id / 0x80);
			while ($id > 0) {
				$result = chr(($id % 0x80) | 0x80).$result;
				$id = floor($id / 0x80);
			}
			return $result;
		};

		// The algorithm is id-ecPublicKey
		// Encode the OID (iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1)
		$algorithm = chr(1 * 40 + 2).$encodeSubIdentifier(840).$encodeSubIdentifier(10045).$encodeSubIdentifier(2).$encodeSubIdentifier(1);
		// Tag number of OID is 6 (X.680, section 8.4)
		// The encoding of OID is primitive (X.690, section 8.19.1)
		// Note: We do not implement the proper length algorithm here, as we know for sure that the short form is used.
		$algorithm = chr(6).chr(mb_strlen($algorithm, '8bit')).$algorithm;
	
		// id-ecPublicKey has got a mandatory parameter, the namedCurve. This is secp256r1.
		// Encode the OID (iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7):
		$namedCurve = chr(1 * 40 + 2).$encodeSubIdentifier(840).$encodeSubIdentifier(10045).$encodeSubIdentifier(3).$encodeSubIdentifier(1).$encodeSubIdentifier(7);
		// Note: We do not implement the proper length algorithm here, as we know for sure that the short form is used.
		$namedCurve = chr(6).chr(mb_strlen($namedCurve, '8bit')).$namedCurve;

		// Tag number of SEQUENCE is 16 (X.680, section 8.4)
		// The encoding of SEQUENCE is constructed (X.690, section 8.9.1)
		// Thus the identifier octet must be the value 16 with bit 6 set to 1 (X.690, section 8.1.2)
		// Note: We do not implement the proper length algorithm here, as we know for sure that the short form is used.
		$algorithmIdentifier = chr(16 | (1 << 5)).chr(mb_strlen($algorithm, '8bit') + mb_strlen($namedCurve, '8bit')).$algorithm.$namedCurve;

		// Tag number of BIT STRING is 3 (X.680, section 8.4)
		// The encoding of the BIT STRING is primitive (X.690, section 10.2)
		// There are no unused bits (X.690, section 8.6.2.2)
		// Note: We do not implement the proper length algorithm here, as we know for sure that the short form is used.
		$subjectPublicKey = chr(3).chr(1 + mb_strlen($point, '8bit')).chr(0).$point;

		// Note: We do not implement the proper length algorithm here, as we know for sure that the short form is used.
		return chr(16 | (1 << 5)).chr(mb_strlen($algorithmIdentifier, '8bit') + mb_strlen($subjectPublicKey, '8bit')).$algorithmIdentifier.$subjectPublicKey;
	}

	/**
	 * Returns the web safe base 64 encoded representation
	 * of the given string.
	 *
	 * This is the encoding given in RFC 4648, Section 5.
	 *
	 * @param    string   $in
	 * @return   string
	 */
	protected function base64url_encode($in) {
		return strtr(base64_encode($in), '+/', '-_');
	}

	/**
	 * Returns the web safe base 64 decoded representation
	 * of the given string.
	 *
	 * This is the encoding given in RFC 4648, Section 5.
	 *
	 * @param   string   $in
	 * @return  string
	 */
	protected function base64url_decode($in) {
		return base64_decode(strtr($in, '-_', '+/'));
	}

	/**
	 * Verifies a signature using the given certificate.
	 */
	protected function openssl_verify_by_cert($data, $signature, $cert) {
		if ($this->opensslBinary === null) {
			return openssl_verify($data, $signature, $cert, 'sha256') === 1;
		}
		else {
			try {
				$dataFile = tempnam(__DIR__.'/tmp', 'data');
				file_put_contents($dataFile, $data);
				$signatureFile = tempnam(__DIR__.'/tmp', 'signature');
				file_put_contents($signatureFile, $signature);
				$certFile = tempnam(__DIR__.'/tmp', 'cert');
				file_put_contents($certFile, $cert);
				$keyFile = tempnam(__DIR__.'/tmp', 'key');
				touch($keyFile);
				exec($this->opensslBinary.' x509 -pubkey -noout -in '.escapeshellarg($certFile).' > '.escapeshellarg($keyFile), $out, $return);
				if ($return != 0) return false;
				exec($this->opensslBinary.' dgst -verify '.escapeshellarg($keyFile).' -signature '.escapeshellarg($signatureFile).' '.escapeshellarg($dataFile).' 2>&1', $out, $return);
				if ($return != 0) return false;

				return true;
			}
			finally {
				@unlink($certFile);
				@unlink($dataFile);
				@unlink($signatureFile);
				@unlink($keyFile);
			}
		}
	}

	/**
	 * Verifies a signature using the given public key.
	 */
	protected function openssl_verify_by_key($data, $signature, $key) {
		if ($this->opensslBinary === null) {
			return openssl_verify($data, $signature, $key, 'sha256') === 1;
		}
		else {
			try {
				$dataFile = tempnam(__DIR__.'/tmp', 'data');
				file_put_contents($dataFile, $data);
				$signatureFile = tempnam(__DIR__.'/tmp', 'signature');
				file_put_contents($signatureFile, $signature);
				$keyFile = tempnam(__DIR__.'/tmp', 'key');
				file_put_contents($keyFile, $key);
				exec($this->opensslBinary.' dgst -verify '.escapeshellarg($keyFile).' -signature '.escapeshellarg($signatureFile).' '.escapeshellarg($dataFile).' 2>&1', $out, $return);
				if ($return != 0) return false;

				return true;
			}
			finally {
				@unlink($dataFile);
				@unlink($signatureFile);
				@unlink($keyFile);
			}
		}
	}
}
