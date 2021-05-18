<?php

function currentFileName() { //return current file name
	return basename($_SERVER['REQUEST_URI'], '?' . $_SERVER['QUERY_STRING']);
}

function baseURL($sub=0) { //return base url for cron jobs
	 $requesturi = explode("?",$_SERVER["REQUEST_URI"]);
	 $subdir =  $requesturi[0];
	 $pageURL = 'http';
	 if(isset($_SERVER["HTTPS"])) { if($_SERVER["HTTPS"] == "on") {$pageURL .= "s";} }
	 $pageURL .= "://";
	 if ($_SERVER["SERVER_PORT"] != "80" && $_SERVER["SERVER_PORT"] != "443") {
	  $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"] . $subdir;
	 } else {
	  $pageURL .= $_SERVER["SERVER_NAME"] . $subdir;
	 }
	 return $pageURL;
}

function randomString($chars=10,$case='mix') { //generate random string
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randstring = '';
    for ($i = 0; $i < $chars; $i++) { $randstring .= $characters[rand(0, strlen($characters) -1)]; }
    if ($case == 'mix')
        return $randstring;
    else if($case == 'small')
        return strtolower($randstring);
    else if($case == 'big')
        return strtoupper($randstring);
}

function curlReturn($url) { //get url with curl
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_VERBOSE, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible;)");
	curl_setopt($ch,CURLOPT_URL, $url);
	$result = curl_exec($ch);
	curl_close($ch);
	return $result;
}

function smartDate($timestamp) {
	$diff = time() - $timestamp;

	if ($diff <= 0) {
		return __('Now');
	}
	else if ($diff < 60) {
		return _x("%d second ago","%d seconds ago",floor($diff));
	}
	else if ($diff < 60*60) {
		return _x("%d minute ago","%d minutes ago",floor($diff/60));
	}
	else if ($diff < 60*60*24) {
		return _x("%d hour ago","%d hours ago",floor($diff/(60*60)));
	}
	else if ($diff < 60*60*24*30) {
		return _x("%d day ago","%d days ago",floor($diff/(60*60*24)));
	}
	else if ($diff < 60*60*24*30*12) {
		return _x("%d month ago","%d months ago",floor($diff/(60*60*24*30)));
	}
	else {
		return _x("%d year ago","%d years ago",floor($diff/(60*60*24*30*12)));
	}
}

function time_ago($date)
{
	if(empty($date)) {
	    return "No date provided";
	}
	$periods = array("second", "minute", "hour", "day", "week", "month", "year", "decade");
	$lengths = array("60","60","24","7","4.35","12","10");
	$now = time();
	$unix_date = strtotime($date);
	// check validity of date
	if(empty($unix_date)) {
	    return "";
	}
	// is it future date or past date
	if($now > $unix_date) {
	    $difference = $now - $unix_date;
	    $tense = "ago";
	} else {
	    $difference = $unix_date - $now;
	    $tense = "from now";
	}
	for($j = 0; $difference >= $lengths[$j] && $j < count($lengths)-1; $j++) {
	    $difference /= $lengths[$j];
	}
	$difference = round($difference);
	if($difference != 1) {
	    $periods[$j].= "s";
	}

	return "$difference $periods[$j] {$tense}";
}
// time_ago('25-05-2000'); //output eg- 21 years ago


function escapeJavaScriptText($string) {
    return str_replace("\n", '\n', str_replace('"', '\"', addcslashes(str_replace("\r", '', (string)$string), "\0..\37'\\")));
}

// ----------------------------------------------------------------------------------------------
// DATA ENCRYPTION FUNCTIONS

// Encrypt Function
function vk_encrypt($encrypt){
	global $config;
	$key = $config['encryption_key'];
    $encrypt = serialize($encrypt);
    $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
    $key = pack('H*', $key);
    $mac = hash_hmac('sha256', $encrypt, substr(bin2hex($key), -32));
    $passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $encrypt.$mac, MCRYPT_MODE_CBC, $iv);
    $encoded = base64_encode($passcrypt).'|'.base64_encode($iv);
    return $encoded;
}
// Decrypt Function
function vk_decrypt($decrypt){
	global $config;
	$key = $config['encryption_key'];
    $decrypt = explode('|', $decrypt.'|');
    $decoded = base64_decode($decrypt[0]);
    $iv = base64_decode($decrypt[1]);
    if(strlen($iv)!==mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)){ return false; }
    $key = pack('H*', $key);
    $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
    $mac = substr($decrypted, -64);
    $decrypted = substr($decrypted, 0, -64);
    $calcmac = hash_hmac('sha256', $decrypted, substr(bin2hex($key), -32));
    if($calcmac!==$mac){ return false; }
    $decrypted = unserialize($decrypted);
    return $decrypted;
}

function is_between_hours($from, $to)
{
    $currentTime    = strtotime(date('H:i'));
    $startTime      = strtotime($from);
    $endTime        = strtotime($to);
    if (
            (
            $startTime < $endTime &&
            $currentTime >= $startTime &&
            $currentTime <= $endTime
            ) ||
            (
            $startTime > $endTime && (
            $currentTime >= $startTime ||
            $currentTime <= $endTime
            )
            )
    ){
        return true;
    }else{
        return false;
    }
}
// is_between_hours(5:00,22:00)


function no_to_words($no)
{
    if($no == 0) {
        return '';

    }else{
        $n =  strlen($no); // 7
        switch ($n) {
            case 3:
                $val = $no/100;
                $val = round($val, 2);
                $finalval =  $val ." Hundred";
                break;
            case 4:
                $val = $no/1000;
                $val = round($val, 2);
                $finalval =  $val ." Thousand";
                break;
            case 5:
                $val = $no/1000;
                $val = round($val, 2);
                $finalval =  $val ." Thousand";
                break;
            case 6:
                $val = $no/100000;
                $val = round($val, 2);
                $finalval =  $val ." Lakh";
                break;
            case 7:
                $val = $no/100000;
                $val = round($val, 2);
                $finalval =  $val ." Lakh";
                break;
            case 8:
                $val = $no/10000000;
                $val = round($val, 2);
                $finalval =  $val ." Crore";
                break;
            case 9:
                $val = $no/10000000;
                $val = round($val, 2);
                $finalval =  $val ." Crore";
                break;
            case 10:
                $val = $no/10000000;
                $val = round($val, 2);
                $finalval =  $val ." Crore";
                break;
            case 11:
                $val = $no/10000000;
                $val = round($val, 2);
                $finalval =  $val ." Crore";
                break;
            case 12:
                $val = $no/10000000;
                $val = round($val, 2);
                $finalval =  $val ." Crore";
                break;
            case 13:
                $val = $no/10000000;
                $val = round($val, 2);
                $finalval =  $val ." Crore";
                break;
            default:
                echo "";
        }
        return $finalval;
    }
}

function remove_json_value($table,$row_id,$column_name,$json_key)
{
    $pre_value = get_value_by_id($table,$column_name,'id',$row_id);
    if ($pre_value != 'NA') {
        $pre_value = json_decode($pre_value,true);
        unset($pre_value[$json_key]);
        if (count($pre_value) > 0) {
            $data[$column_name] = json_encode($pre_value);
        }else{
            $data[$column_name] = 'NA';
        }
        $CI =& get_instance();
        $CI->db->where('id',$row_id);
        $CI->db->update($table,$data);
    }
}

function pre()
{
    echo (php_sapi_name() !== 'cli') ? '<pre>' : '';
    foreach(func_get_args() as $arg){
        echo preg_replace('#\n{2,}#', "\n", print_r($arg, true));
    }
    echo (php_sapi_name() !== 'cli') ? '</pre>' : '';exit();
}

function rand_color() { //generate random color
    return '#' . str_pad(dechex(mt_rand(0, 0xFFFFFF)), 6, '0', STR_PAD_LEFT);
}

function getGravatar($email,$size) { //get gravatar image for the given email address
	global $database;

	$grav_url = "https://www.gravatar.com/avatar/" . md5( strtolower( trim( $email ) ) ) . "?d=mm" . "&s=" . $size;
	$avatar = $database->get("people", "avatar", [ "email" => strtolower($email) ]);

	if($avatar != "") { return "data:image/jpeg;base64," . base64_encode($avatar); }

	else return $grav_url;
}

function rcopy($from, $to)
{ //copy file from to
    if (file_exists($to)) {
        rrmdir($to);
    }
    if (is_dir($from)) {
        mkdir($to, 0777, true);
        $files = scandir($from);
        foreach ($files as $file) {
            if ($file != "." && $file != "..") {
                rcopy($from . DIRECTORY_SEPARATOR . $file, $to . DIRECTORY_SEPARATOR . $file);
            }
        }
    } else if (file_exists($from)) {
        copy($from, $to);
        chmod($to, 0777);
    }
}

// in_array_r($search_val,$all_data);
function in_array_r($needle, $haystack, $strict = false) {
    foreach ($haystack as $item) {
        if (($strict ? $item === $needle : $item == $needle) || (is_array($item) && in_array_r($needle, $item, $strict))) {
            return true;
        }
    }

    return false;
}

?>
