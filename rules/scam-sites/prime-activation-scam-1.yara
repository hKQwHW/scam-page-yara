rule TechSupportScam1
{
    // http://ziltzwebsol.online/tvmounting/sample1/secondpage.php?phone=%2B1-808-210-3358&status=1
    strings:
        $a1 = "Your Code Has Been Redeemed Successfully"
        $b1 = "Click Here To Activate Prime"
        $c1 = "Congratulations"
        
        $a2 = "Next Step: Call prime Support for account Validation & Activation"
        $b2 = "Your Code Has Been Redeemed"
    
    condition:
        ($a1 and $b1 and $c1) or ($a2 and $b2)
}
