rule TechSupportScam1
{
    // http://ziltzwebsol.online/tvmounting/sample1/secondpage.php?phone=%2B1-808-210-3358&status=1
    strings:
        $a = "Your Code Has Been Redeemed Successfully"
        $b = "Click Here To Activate Prime"
        $c = "Congratulations"
    
    condition:
        $a and $b and $c
}
