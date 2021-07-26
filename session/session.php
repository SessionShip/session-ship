<?php

/**
 * @author RecepBagiryanik
 * @github RecepBagiryanik
 * This library fix php session hijacking and more weakness. Increase security!
 * SessionShip!
 */

namespace PHP\Session;

error_reporting(0);
define("__SERVER__", $_SERVER["DOCUMENT_ROOT"]);
class sessionLibrary
{
    //Set session key, required variable! NOT SHARE WITH ANYONE!
    public static $sessionKey = 1234;
    //Set cookie name, required variable!
    public static $cookieName = "ws-session";
    public function __construct()
    {
        //Do not handle this part.
        if ($this->checkSession()) {
            if($this->readValue("userIP") != $this->getUserIP()) {
                $this->sessionDestroy();
                return false;
            } else {
                if($this->readValue("userAgent") != $_SERVER["HTTP_USER_AGENT"]) {
                    $this->sessionDestroy();
                    return false;
                } else {
                    return true;
                }
            }
            
            if($this->readValue("userIP") == false) {
                $this->sessionDestroy();
            }
        }
    }

    public function getUserIP()
    {
        //This function allows you to get the ip address of the user.
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        }
        return $_SERVER["REMOTE_ADDR"];
    }

    public function createSession()
    {
        //Create Session, this function required.
        if ($this->checkSession()) {
            return false;
        } else {
            $randomToken = md5(uniqid());
            $sessionArray = json_encode(array("userIP", $this->getUserIP(), "userAgent", $_SERVER["HTTP_USER_AGENT"]));
            $sessionId = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            $arraySession = json_encode(array($randomToken, $sessionId));
            file_put_contents(__DIR__ . "/storage/sessions.txt", file_get_contents(__DIR__ . "/storage/sessions.txt") . $arraySession . "&");
            setcookie(self::$cookieName, $randomToken);
        }
    }

    public function getSessionId()
    {
        //Reading the session's cookie information.
        return $_COOKIE[self::$cookieName];
    }

    public function sessionDestroy()
    {
        //Terminates the session.
        if ($this->checkSession()) {
            setcookie(self::$cookieName, "", strtotime("-365 years"));
            $content = file_get_contents(__DIR__ . "/storage/sessions.txt");
            $explodeContent = explode("&", $content);
            $found2 = preg_grep('["' . $this->getSessionId() . '","(.*)"]', $explodeContent);
            $found = array_search(max($found2), $explodeContent);
            $newContent = str_replace(max($found2) . "&", "", $content);
            file_put_contents(__DIR__ . "/storage/sessions.txt", $newContent);
            return true;
        }
    }

    public function addValue($valueName, $value)
    {
        //Adding value to the session.
        if ($this->readValue($valueName) == false) {
            $content = file_get_contents(__DIR__ . "/storage/sessions.txt");
            $explodeContent = explode("&", $content);
            $found2 = preg_grep('["' . $this->getSessionId() . '","(.*)"]', $explodeContent);
            $found = array_search(max($found2), $explodeContent);
            $decoded = json_decode($explodeContent[$found], true);
            $decodeOne = openssl_decrypt($decoded[1], "AES-256-CBC", self::$sessionKey);
            $jsonDecoded = json_decode($decodeOne);
            array_push($jsonDecoded, $valueName);
            array_push($jsonDecoded, $value);
            $sessionArray = json_encode($jsonDecoded);
            $encryptData = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            $readContent = '["' . $this->getSessionId() . '","' . $encryptData . '"]';
            $newContent = str_replace(max($found2), $readContent, $content);
            file_put_contents(__DIR__ . "/storage/sessions.txt", $newContent);
            return true;
        } else {
            return false;
        }
    }

    public function editValue($valueName, $value)
    {
        //Allows you to change the session value.
        if ($this->readValue($valueName) == false) {
            return false;
        } else {
            $content = file_get_contents(__DIR__ . "/storage/sessions.txt");
            $explodeContent = explode("&", $content);
            $found2 = preg_grep('["' . $this->getSessionId() . '","(.*)"]', $explodeContent);
            $found = array_search(max($found2), $explodeContent);
            $decoded = json_decode($explodeContent[$found], true);
            $decodeOne = openssl_decrypt($decoded[1], "AES-256-CBC", self::$sessionKey);
            $jsonDecoded = json_decode($decodeOne);
            $search = array_search($valueName, $jsonDecoded);
            $replace = array($search + 1 => $value);
            $newContent = array_replace($jsonDecoded, $replace);
            $sessionArray = json_encode($newContent);
            $encryptData = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            $readContent = '["' . $this->getSessionId() . '","' . $encryptData . '"]';
            $newContent = str_replace(max($found2), $readContent, $content);
            file_put_contents(__DIR__ . "/storage/sessions.txt", $newContent);
        }
    }

    public function deleteValue($valueName)
    {
        //Delete value
        if ($this->readValue($valueName) == false) {
            return false;
        } else {
            $content = file_get_contents(__DIR__ . "/storage/sessions.txt");
            $explodeContent = explode("&", $content);
            $found2 = preg_grep('["' . $this->getSessionId() . '","(.*)"]', $explodeContent);
            $found = array_search(max($found2), $explodeContent);
            $decoded = json_decode($explodeContent[$found], true);
            $decodeOne = openssl_decrypt($decoded[1], "AES-256-CBC", self::$sessionKey);
            $jsonDecoded = json_decode($decodeOne);
            $search = array_search($valueName, $jsonDecoded);
            unset($jsonDecoded[$search]);
            unset($jsonDecoded[$search + 1]);
            $sessionArray = json_encode($jsonDecoded);
            $encryptData = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            $readContent = '["' . $this->getSessionId() . '","' . $encryptData . '"]';
            $newContent = str_replace(max($found2), $readContent, $content);
            file_put_contents(__DIR__ . "/storage/sessions.txt", $newContent);
            return true;
        }
    }

    public function checkValue($valueName)
    {
        //You check if the session value exists, it returns false or true.
        if ($this->readValue($valueName) == false) {
            return false;
        } else {
            return true;
        }
    }

    public function readValue($valueName)
    {
        //It allows you to read the session value, use echo to project it to the screen.
        $content = file_get_contents(__DIR__ . "/storage/sessions.txt");
        $explodeContent = explode("&", $content);
        $found = preg_grep('["' . $this->getSessionId() . '","(.*)"]', $explodeContent);
        $found = array_search(max($found), $explodeContent);
        $decodedContent = json_decode($explodeContent[$found], true);
        $foundT = array_search($this->getSessionId(), $decodedContent);
        $decodeOne = openssl_decrypt($decodedContent[$foundT + 1], "AES-256-CBC", self::$sessionKey);
        $decoded = json_decode($decodeOne);
        $found = array_search($valueName, $decoded);
        if ($found > -1) {
            return $decoded[$found + 1];
        } else {
            return false;
        }
    }

    public function checkSession()
    {
        //Check if the session exists.
        if (isset($_COOKIE[self::$cookieName])) {
            return true;
        } else {
            return false;
        }
    }
}
