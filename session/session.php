<?php

/**
 * @author RecepBagiryanik
 * @github RecepBagiryanik
 * This library fix php session hijacking and more weakness. Increase security!
 */

namespace PHP\Session;


define("__SERVER__", $_SERVER["DOCUMENT_ROOT"]);
class sessionLibrary
{
    //Set session key! NOT SHARE WITH ANYONE!
    public static $sessionKey = 1234;
    public static $cookieName = "ws-session";
    public function __construct()
    {
        //Check user IP
        if ($this->checkSession()) {
            if($this->getSessionValue("userIP") != $this->getUserIP()) {
                $this->sessionDestroy();
                return false;
            } else {
                if($this->getSessionValue("userAgent") != $_SERVER["HTTP_USER_AGENT"]) {
                    $this->sessionDestroy();
                    return false;
                } else {
                    return true;
                }
            }
        }
    }

    public function getUserIP()
    {
        //Get User IP
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        }
        return $_SERVER["REMOTE_ADDR"];
    }

    public function createSession($sessionName, $sessionValue)
    {
        //Create Session, this function required.
        if ($this->checkSession()) {
            return false;
        } else {
            $sessionArray = json_encode(array($sessionName, $sessionValue, "userIP", $this->getUserIP(), "userAgent" => $_SERVER["HTTP_USER_AGENT"]));
            $sessionId = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            setcookie(self::$cookieName, $sessionId);
        }
    }

    public function getSessionId()
    {
        //Reading the session's cookie information.
        return $_COOKIE[self::$cookieName];
    }

    public function sessionDestroy()
    {
        //Session Destroy
        if ($this->checkSession()) {
            setcookie(self::$cookieName, "", strtotime("-365 years"));
        }
    }

    public function addValue($valueName, $value)
    {
        //Adding value to the session.
        if ($this->getSessionValue($valueName) == false) {
            $decodeOne = openssl_decrypt($this->getSessionId(), "AES-256-CBC", self::$sessionKey);
            $decoded = json_decode($decodeOne);
            array_push($decoded, $valueName);
            array_push($decoded, $value);
            $sessionArray = json_encode($decoded);
            $encryptData = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            setcookie(self::$cookieName, $encryptData);
            return true;
        } else {
            return false;
        }
    }

    public function editValue($valueName, $value)
    {
        //Allows you to change the session value.
        if($this->getSessionValue($valueName) == false) {
            return false;
        } else {
            $decodeOne = openssl_decrypt($this->getSessionId(), "AES-256-CBC", self::$sessionKey);
            $decoded = json_decode($decodeOne);
            $found = array_search($valueName, $decoded);
            $arrayOne = array($found => $valueName, $found+1 => $value);
            $edited = array_replace($decoded, $arrayOne);
            $sessionArray = json_encode($edited);
            $encryptData = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            setcookie(self::$cookieName, $encryptData);
        }
    }

    public function deleteValue($valueName)
    {
        //Delete value
        if ($this->getSessionValue($valueName) == false) {
            return false;
        } else {
            $decodeOne = openssl_decrypt($this->getSessionId(), "AES-256-CBC", self::$sessionKey);
            $decoded = json_decode($decodeOne);
            $found = array_search($valueName, $decoded);
            unset($decoded[$found]);
            unset($decoded[$found + 1]);
            $sessionArray = json_encode($decoded);
            $encryptData = openssl_encrypt($sessionArray, "AES-256-CBC", self::$sessionKey);
            setcookie(self::$cookieName, $encryptData);
            return true;
        }
    }

    public function checkValue($valueName)
    {
        if($this->getSessionValue($valueName) == false) {
            return false;
        } else {
            return true;
        }
    }

    public function getSessionValue($valueName)
    {
        //Read session value, use the echo.
        error_reporting(0);
        $decodeOne = openssl_decrypt($this->getSessionId(), "AES-256-CBC", self::$sessionKey);
        $decoded = json_decode($decodeOne);
        $found = array_search($valueName, $decoded);
        if (!empty($found)) {
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
