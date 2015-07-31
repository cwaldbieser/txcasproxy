<?php
# txcasproxy PHP integration example.
?>
<html>
<head>
<title></title>
</head>
<body>
<h2>Server Variables</h2>
<pre>
<?php
print htmlspecialchars(print_r($_SERVER, $return=TRUE));
?>
</pre>
<?php
$username = $_SERVER['HTTP_REMOTE_USER'];
if($username)
{
?>
<h2>txcasproxy CAS Authenticated User Info for <strong><?php echo htmlspecialchars($username);?></strong></h2>
<pre>
<?php
    $ch = curl_init(); 
    // set url
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:9444/$username");
    //return the transfer as a string
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    // $output contains the output string
    $output = curl_exec($ch);
    // close curl resource to free up system resources
    curl_close($ch);      
    $jsonIterator = new RecursiveIteratorIterator(
        new RecursiveArrayIterator(json_decode($output, TRUE)),
        RecursiveIteratorIterator::SELF_FIRST);

    foreach ($jsonIterator as $key => $val) 
    {
        if(is_array($val)) 
        {
            echo htmlspecialchars("$key:\n");
        } 
        else 
        {
            echo htmlspecialchars("$key => $val\n");
        }
    }
?>
</pre>
<?php
}
else
{
?>
<h2>No REMOTE_USER</h2>
<?php
}
?>
</body>
</html>
<?php
?>
