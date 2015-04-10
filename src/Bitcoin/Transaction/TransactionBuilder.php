<?php

namespace BitWasp\Bitcoin\Transaction;

use BitWasp\Bitcoin\Address\AddressInterface;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Buffertools\Buffer;
use BitWasp\Bitcoin\Crypto\EcAdapter\EcAdapterInterface;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Crypto\Random\Rfc6979;
use BitWasp\Bitcoin\Key\PrivateKeyInterface;
use BitWasp\Bitcoin\Key\PublicKeyInterface;
use BitWasp\Bitcoin\Script\Classifier\OutputClassifier;
use BitWasp\Bitcoin\Script\RedeemScript;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Bitcoin\Signature\SignatureFactory;
use BitWasp\Bitcoin\Signature\SignatureCollection;
use BitWasp\Bitcoin\Signature\SignatureHashInterface;


/**
 * Class TransactionBuilder
 * @package BitWasp\Bitcoin\Transaction
 */
class TransactionBuilder
{
    /**
     * @var TransactionInterface
     */
    private $transaction;

    /**
     * @var bool
     */
    private $deterministicSignatures = true;

    /**
     * @var TransactionBuilderInputState[]
     */
    private $inputStates = [];

    /**
     * @var EcAdapterInterface
     */
    private $ecAdapter;

    /**
     * @param EcAdapterInterface $ecAdapter
     * @param TransactionInterface $tx
     * @internal param Math $math
     * @internal param GeneratorPoint $generatorPoint
     */
    public function __construct(EcAdapterInterface $ecAdapter, TransactionInterface $tx = null)
    {
        $this->transaction = $tx ?: TransactionFactory::create();
        $this->ecAdapter = $ecAdapter;
    }

    /**
     * Create an input for this transaction spending $tx's output, $outputToSpend.
     *
     * @param TransactionInterface $tx
     * @param $outputToSpend
     * @return $this
     */
    public function spendOutput(TransactionInterface $tx, $outputToSpend)
    {
        // Check TransactionOutput exists
        $tx->getOutputs()->getOutput($outputToSpend);

        $this->transaction
            ->getInputs()
            ->addInput(new TransactionInput($tx->getTransactionId(), $outputToSpend));

        return $this;
    }

    /**
     * Create an output paying $value to an Address.
     *
     * @param AddressInterface $address
     * @param $value
     * @return $this
     */
    public function payToAddress(AddressInterface $address, $value)
    {
        // Create Script from address, then create an output.
        $this->transaction->getOutputs()->addOutput(new TransactionOutput(
            $value,
            ScriptFactory::scriptPubKey()->payToAddress($address)
        ));
        return $this;
    }

    /**
     * @param TransactionBuilderInputState $inputState
     * @throws \Exception
     */
    private function extractSigs(TransactionBuilderInputState $inputState)
    {
        // Todo: should wrap in a try {} since this is where we deal with data from outside?
        //  - fromHex() functions can fail hard, from input that mightnt be safe to rely on.
        //  - should it die here, or should it just fail to find a signature, and regenerate with an empty script?

        $outParse = $inputState->getPreviousOutputScript()->getScriptParser()->parse();
        $inParse = $inputState->getInput()->getScript()->getScriptParser()->parse();
        $sSize = count($inParse);

        // Parse a SignatureCollection from the script, based on the outputScript
        // $this->inputSigs[$forInput] = new TransactionSignatureCollection();

        switch ($inputState->getScriptType()) {
            case OutputClassifier::PAYTOPUBKEYHASH:
                if ($sSize == 2) {
                    // TODO: TransactionSignatureCollection - so pass a TransactionSignature
                    // ScriptSig: [vchSig] [vchPubKey]
                    // ScriptPubKey: OP_DUP OP_HASH160 0x14 [hash] OP_EQUALVERIFY OP_CHECKSIG
                    $inputState->setSignatures([SignatureFactory::fromHex($inParse[0], $this->ecAdapter->getMath())]);
                    $inputState->setPublicKeys([PublicKeyFactory::fromHex($inParse[1])]);
                }

                break;
            case OutputClassifier::PAYTOPUBKEY:
                if ($sSize == 1) {
                    // TODO: TransactionSignatureCollection - so pass a TransactionSignature
                    // ScriptSig: [vchSig] [vchPubKey]
                    // ScriptPubKey: [vchPubKey] OP_CHECKSIG
                    $inputState->setSignatures([SignatureFactory::fromHex($inParse[0], $this->ecAdapter->getMath())]);
                    $inputState->setPublicKeys([PublicKeyFactory::fromHex($outParse[0])]);
                }

                break;
            case OutputClassifier::PAYTOSCRIPTHASH:
            case OutputClassifier::MULTISIG:
                // TODO: TransactionSignatureCollection - so pass a TransactionSignature
                // ScriptSig: OP_0 vector<vchSig> [redeemScript]
                // ScriptPubKey:: OP_HASH160 0x14 [hash] OP_EQUAL
                if (!$inputState->getRedeemScript()) {
                    throw new \Exception('Must pass message hash / redeemScript to parse signatures');
                }

                $script = end($inParse);

                // Matches, and there is at least one signature.
                if ($script !== $inputState->getRedeemScript()->getHex() || $sSize < 3) {
                    break;
                }

                // Associate a collection of signatures with their public keys
                foreach(array_slice($inParse, 1, -2) as $idx => $buffer) {
                    if ($buffer instanceof Buffer) {
                        $sig = SignatureFactory::fromHex($buffer->getHex());
                        $inputState->setSignature($idx, $sig);
                    }
                }

                // Extract public keys
                $inputState->setPublicKeys($inputState->getRedeemScript()->getKeys());

                break;
        }
    }

    /**
     * @param $forInput
     * @return \BitWasp\Bitcoin\Script\Script
     */
    private function regenerateScript($forInput)
    {
        if (!isset($this->inputStates[$forInput])) {
            return $this->transaction->getInputs()->getInput($forInput)->getScript();
        }

        $inputState = $this->inputStates[$forInput];

        switch ($inputState->getPreviousOutputClassifier()) {
            case OutputClassifier::PAYTOPUBKEYHASH:
                $script = ScriptFactory::scriptSig()->payToPubKeyHash($inputState->getSignatures()[0], $inputState->getPublicKeys()[0]);
                break;
            case OutputClassifier::PAYTOPUBKEY:
                $script = ScriptFactory::scriptSig()->payToPubKey($inputState->getSignatures()[0], $inputState->getPublicKeys()[0]);
                break;
            case OutputClassifier::PAYTOSCRIPTHASH:
            case OutputClassifier::MULTISIG:
                // Todo: separate P2SH / multisig cases, and resolve dependency on txHash.
                $script = ScriptFactory::scriptSig()->multisigP2sh(
                    $inputState->getRedeemScript(),
                    $inputState->getSignatures(),
                    $inputState->getRedeemScript()->getScriptHash()
                );
                break;
            default:
                // No idea how to classify this input!
                // Should we defer to $this->transaction->getInputs()->getInput($forInput)->getScript() like above?
                $script = ScriptFactory::create();
                break;
        }

        return $script;
    }

    /**
     * @param ScriptInterface $script
     * @param $value
     * @return TransactionBuilder
     */
    public function payToScriptHash(ScriptInterface $script, $value)
    {
        return $this->payToAddress($script->getAddress(), $value);
    }

    /**
     * @return $this
     */
    public function useRandomSignatures()
    {
        $this->deterministicSignatures = false;
        return $this;
    }

    /**
     * @return $this
     */
    public function useDeterministicSignatures()
    {
        $this->deterministicSignatures = true;
        return $this;
    }

    /**
     * @param PrivateKeyInterface $privKey
     * @param Buffer $hash
     * @return \BitWasp\Bitcoin\Signature\Signature
     */
    public function sign(PrivateKeyInterface $privKey, Buffer $hash)
    {
        $random = ($this->deterministicSignatures
            ? new Rfc6979($this->ecAdapter->getMath(), $this->ecAdapter->getGenerator(), $privKey, $hash, 'sha256')
            : new Random());

        return $this->ecAdapter->sign($hash, $privKey, $random);
    }

    /**
     * @param PrivateKeyInterface $privateKey
     * @param ScriptInterface $outputScript
     * @param $inputToSign
     * @param RedeemScript $redeemScript
     * @param int $sigHashType
     * @return $this
     * @throws \Exception
     */
    public function signInputWithKey(
        PrivateKeyInterface $privateKey,
        ScriptInterface $outputScript,
        $inputToSign,
        RedeemScript $redeemScript = null,
        $sigHashType = null
    ) {

        $input = $this->transaction->getInputs()->getInput($inputToSign);

        if (!isset($this->inputStates[$inputToSign])) {
            $inputState = new TransactionBuilderInputState($input);
            $inputState->setSigHashType($sigHashType ?: SignatureHashInterface::SIGHASH_ALL);
        } else {
            $inputState = $this->inputStates[$inputToSign];

            if ($sigHashType && $inputState->getSigHashType() !== $sigHashType) {
                throw new \InvalidArgumentException();
            }
        }

        if ($redeemScript) {
            $inputState->setRedeemScript($redeemScript);
            $inputState->setScriptType(OutputClassifier::MULTISIG);
            $inputState->setPreviousOutputScript($redeemScript->getOutputScript());

        } else {
            $classifier = new OutputClassifier($outputScript);

            $inputState->setScriptType($classifier->classify());
            $inputState->setPreviousOutputScript($outputScript);
        }

        $this->extractSigs($inputState);

        // force myself to use $inputState
        unset($redeemScript, $outputScript, $sigHashType);

        $prevOutType = $inputState->getScriptType();

        $parse = $inputState->getPreviousOutputScript()->getScriptParser()->parse();
        $signatureHash = $this->transaction->signatureHash();
        $pubKeyHash = $privateKey->getPubKeyHash();

        if ($prevOutType == OutputClassifier::PAYTOPUBKEYHASH) {
            if ($parse[2]->getBinary() == $pubKeyHash->getBinary()) {
                $hash = $signatureHash->calculate($inputState->getPreviousOutputScript(), $inputToSign, $inputState->getSigHashType());
                $inputState->setSignatures([$this->sign($privateKey, $hash)]);
            }

            // TODO: P2SH !== multisig, more work to be done here..
        } else if (in_array($prevOutType, [OutputClassifier::PAYTOSCRIPTHASH, OutputClassifier::MULTISIG])) {
            if (!$inputState->getRedeemScript()) {
                throw new \Exception('Redeem script should be passed when signing a p2sh input');
            }

            if ($parse[1]->getBinary() == $inputState->getRedeemScript()->getScriptHash()->getBinary()) {
                $hash = $signatureHash->calculate($inputState->getRedeemScript()->getOutputScript(), $inputToSign, $inputState->getSigHashType());
                foreach ($inputState->getRedeemScript()->getKeys() as $idx => $key) {
                    if ($pubKeyHash->getBinary() == $key->getPubKeyHash()->getBinary()) {
                        $inputState->setSignature($idx, $this->sign($privateKey, $hash));
                    }
                }
            }
        } else {
            throw new \Exception('Unsupported transaction type');
        }

        return $this;
    }

    /**
     * @return Transaction
     */
    public function getTransaction()
    {
        $transaction = $this->transaction;
        $inCount = count($transaction->getInputs());
        for ($i = 0; $i < $inCount; $i++) {
            $newScript = $this->regenerateScript($i);
            $transaction->getInputs()->getInput($i)->setScript($newScript);
        }

        return $transaction;
    }
}
