<?php 
/**
 * @author RecepBagiryanik, MamiWebDev
 * @github RecepBagiryanik, MamiWebDev
 * SessionShip functions test file.
 */
require __DIR__ . "/session/session.php";
$session = new \PHP\Session\sessionLibrary();
//Create Session, this function required.
$session->createSession("name","Recep");
//Reading the session's cookie information.
$session->getSessionId();
//Adding value to the session.
$session->addValue("surname", "Bagiryanik");
//Allows you to change the session value.
$session->editValue("surname","Jhs");
//Delete value
$session->deleteValue("surname");
//You check if the session value exists, it returns false or true.
$session->checkValue("name"); //true
//It allows you to read the session value, use echo to project it to the screen.
$session->getSessionValue("name");
//Check if the session exists , it returns false or true.
$session->checkSession(); //true
//Terminates the session.
$session->sessionDestroy();
//This function allows you to get the ip address of the user.
$session->getUserIP();
?>
