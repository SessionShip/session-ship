<?php 
/**
 * @author RecepBagiryanik
 * @github RecepBagiryanik
 * Session library test file.
 */
require __DIR__ . "/session/session.php";
$session = new \PHP\Session\sessionLibrary();

if(empty($session->checkSession("csrftoken"))) {
    $session->addValue("csrftoken", md5(uniqid()));
}

if(isset($_POST["send"])) {
    if($session->getSessionValue("csrftoken") != $_POST["csrftoken"]) {
        echo "false";
    } else {
        $session->editValue("csrftoken", md5(uniqid()));
        echo "true";
    }
}

//$flex = openssl_decrypt($session->getSessionId(), "AES-256-CBC", "1234");
//print_r(json_decode($flex));
?>
<h4>LOGİN - TEST</h4>
<form action="" method="post">
    <input type="text" name="username">
    <input type="text" name="csrftoken" value="<?php echo $session->getSessionValue("csrftoken"); ?>">
    <input type="submit" name="send">
</form>