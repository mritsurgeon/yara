import "math"

private rule tree0
{
    strings:
		$s0 = "Christophermouth" fullword

    condition:
((#s0 <= 0.5)
 and ( (filesize <= 439.0)
 or  (filesize > 439.0)
 and (  (filesize > 1455.0)
 and (   (filesize <= 1897.5)
))) or (#s0 > 0.5)
)
}



private rule tree1
{
    strings:


    condition:
((filesize <= 416.5)
 or (filesize > 416.5)
 and ( (filesize > 1470.5)
 and (  (filesize <= 1909.0)
)))
}



private rule tree2
{
    strings:


    condition:
((filesize <= 428.0)
 or (filesize > 428.0)
 and ( (filesize > 1457.0)
 and (  (filesize <= 1898.5)
)))
}



private rule tree3
{
    strings:


    condition:
((filesize <= 428.0)
 or (filesize > 428.0)
 and ( (filesize > 1470.5)
 and (  (filesize <= 1898.0)
)))
}



private rule tree4
{
    strings:
		$s0 = "Christophermouth" fullword

    condition:
((#s0 <= 0.5)
 and ( (filesize <= 426.5)
 or  (filesize > 426.5)
 and (  (filesize > 1470.5)
 and (   (filesize <= 1898.5)
))) or (#s0 > 0.5)
)
}



private rule tree5
{
    strings:


    condition:
((filesize <= 418.0)
 or (filesize > 418.0)
 and ( (filesize > 1470.5)
 and (  (filesize <= 1897.5)
)))
}



private rule tree6
{
    strings:


    condition:
((filesize <= 428.0)
 or (filesize > 428.0)
 and ( (filesize > 1470.5)
 and (  (filesize <= 1902.5)
)))
}



private rule tree7
{
    strings:
		$s0 = "Christophermouth" fullword

    condition:
((#s0 <= 0.5)
 and ( (filesize <= 418.0)
 or  (filesize > 418.0)
 and (  (filesize > 1455.0)
 and (   (filesize <= 1898.0)
))) or (#s0 > 0.5)
)
}



private rule tree8
{
    strings:
		$s0 = "Christophermouth" fullword

    condition:
((#s0 <= 0.5)
 and ( (filesize <= 418.0)
 or  (filesize > 418.0)
 and (  (filesize > 1470.5)
 and (   (filesize <= 1909.5)
))) or (#s0 > 0.5)
)
}



private rule tree9
{
    strings:
		$s0 = "Christophermouth" fullword

    condition:
((#s0 <= 0.5)
 and ( (filesize <= 418.0)
 or  (filesize > 418.0)
 and (  (filesize > 1457.0)
 and (   (filesize <= 1898.0)
))) or (#s0 > 0.5)
)
}



rule PII_detector_RF
{
    condition:
	(tree0 and tree1 and tree2 and tree3 and tree4)
		 or (tree0 and tree1 and tree2 and tree3 and tree5)
		 or (tree0 and tree1 and tree2 and tree3 and tree6)
		 or (tree0 and tree1 and tree2 and tree3 and tree7)
		 or (tree0 and tree1 and tree2 and tree3 and tree8)
		 or (tree0 and tree1 and tree2 and tree3 and tree9)
		 or (tree0 and tree1 and tree2 and tree4 and tree5)
		 or (tree0 and tree1 and tree2 and tree4 and tree6)
		 or (tree0 and tree1 and tree2 and tree4 and tree7)
		 or (tree0 and tree1 and tree2 and tree4 and tree8)
		 or (tree0 and tree1 and tree2 and tree4 and tree9)
		 or (tree0 and tree1 and tree2 and tree5 and tree6)
		 or (tree0 and tree1 and tree2 and tree5 and tree7)
		 or (tree0 and tree1 and tree2 and tree5 and tree8)
		 or (tree0 and tree1 and tree2 and tree5 and tree9)
		 or (tree0 and tree1 and tree2 and tree6 and tree7)
		 or (tree0 and tree1 and tree2 and tree6 and tree8)
		 or (tree0 and tree1 and tree2 and tree6 and tree9)
		 or (tree0 and tree1 and tree2 and tree7 and tree8)
		 or (tree0 and tree1 and tree2 and tree7 and tree9)
		 or (tree0 and tree1 and tree2 and tree8 and tree9)
		 or (tree0 and tree1 and tree3 and tree4 and tree5)
		 or (tree0 and tree1 and tree3 and tree4 and tree6)
		 or (tree0 and tree1 and tree3 and tree4 and tree7)
		 or (tree0 and tree1 and tree3 and tree4 and tree8)
		 or (tree0 and tree1 and tree3 and tree4 and tree9)
		 or (tree0 and tree1 and tree3 and tree5 and tree6)
		 or (tree0 and tree1 and tree3 and tree5 and tree7)
		 or (tree0 and tree1 and tree3 and tree5 and tree8)
		 or (tree0 and tree1 and tree3 and tree5 and tree9)
		 or (tree0 and tree1 and tree3 and tree6 and tree7)
		 or (tree0 and tree1 and tree3 and tree6 and tree8)
		 or (tree0 and tree1 and tree3 and tree6 and tree9)
		 or (tree0 and tree1 and tree3 and tree7 and tree8)
		 or (tree0 and tree1 and tree3 and tree7 and tree9)
		 or (tree0 and tree1 and tree3 and tree8 and tree9)
		 or (tree0 and tree1 and tree4 and tree5 and tree6)
		 or (tree0 and tree1 and tree4 and tree5 and tree7)
		 or (tree0 and tree1 and tree4 and tree5 and tree8)
		 or (tree0 and tree1 and tree4 and tree5 and tree9)
		 or (tree0 and tree1 and tree4 and tree6 and tree7)
		 or (tree0 and tree1 and tree4 and tree6 and tree8)
		 or (tree0 and tree1 and tree4 and tree6 and tree9)
		 or (tree0 and tree1 and tree4 and tree7 and tree8)
		 or (tree0 and tree1 and tree4 and tree7 and tree9)
		 or (tree0 and tree1 and tree4 and tree8 and tree9)
		 or (tree0 and tree1 and tree5 and tree6 and tree7)
		 or (tree0 and tree1 and tree5 and tree6 and tree8)
		 or (tree0 and tree1 and tree5 and tree6 and tree9)
		 or (tree0 and tree1 and tree5 and tree7 and tree8)
		 or (tree0 and tree1 and tree5 and tree7 and tree9)
		 or (tree0 and tree1 and tree5 and tree8 and tree9)
		 or (tree0 and tree1 and tree6 and tree7 and tree8)
		 or (tree0 and tree1 and tree6 and tree7 and tree9)
		 or (tree0 and tree1 and tree6 and tree8 and tree9)
		 or (tree0 and tree1 and tree7 and tree8 and tree9)
		 or (tree0 and tree2 and tree3 and tree4 and tree5)
		 or (tree0 and tree2 and tree3 and tree4 and tree6)
		 or (tree0 and tree2 and tree3 and tree4 and tree7)
		 or (tree0 and tree2 and tree3 and tree4 and tree8)
		 or (tree0 and tree2 and tree3 and tree4 and tree9)
		 or (tree0 and tree2 and tree3 and tree5 and tree6)
		 or (tree0 and tree2 and tree3 and tree5 and tree7)
		 or (tree0 and tree2 and tree3 and tree5 and tree8)
		 or (tree0 and tree2 and tree3 and tree5 and tree9)
		 or (tree0 and tree2 and tree3 and tree6 and tree7)
		 or (tree0 and tree2 and tree3 and tree6 and tree8)
		 or (tree0 and tree2 and tree3 and tree6 and tree9)
		 or (tree0 and tree2 and tree3 and tree7 and tree8)
		 or (tree0 and tree2 and tree3 and tree7 and tree9)
		 or (tree0 and tree2 and tree3 and tree8 and tree9)
		 or (tree0 and tree2 and tree4 and tree5 and tree6)
		 or (tree0 and tree2 and tree4 and tree5 and tree7)
		 or (tree0 and tree2 and tree4 and tree5 and tree8)
		 or (tree0 and tree2 and tree4 and tree5 and tree9)
		 or (tree0 and tree2 and tree4 and tree6 and tree7)
		 or (tree0 and tree2 and tree4 and tree6 and tree8)
		 or (tree0 and tree2 and tree4 and tree6 and tree9)
		 or (tree0 and tree2 and tree4 and tree7 and tree8)
		 or (tree0 and tree2 and tree4 and tree7 and tree9)
		 or (tree0 and tree2 and tree4 and tree8 and tree9)
		 or (tree0 and tree2 and tree5 and tree6 and tree7)
		 or (tree0 and tree2 and tree5 and tree6 and tree8)
		 or (tree0 and tree2 and tree5 and tree6 and tree9)
		 or (tree0 and tree2 and tree5 and tree7 and tree8)
		 or (tree0 and tree2 and tree5 and tree7 and tree9)
		 or (tree0 and tree2 and tree5 and tree8 and tree9)
		 or (tree0 and tree2 and tree6 and tree7 and tree8)
		 or (tree0 and tree2 and tree6 and tree7 and tree9)
		 or (tree0 and tree2 and tree6 and tree8 and tree9)
		 or (tree0 and tree2 and tree7 and tree8 and tree9)
		 or (tree0 and tree3 and tree4 and tree5 and tree6)
		 or (tree0 and tree3 and tree4 and tree5 and tree7)
		 or (tree0 and tree3 and tree4 and tree5 and tree8)
		 or (tree0 and tree3 and tree4 and tree5 and tree9)
		 or (tree0 and tree3 and tree4 and tree6 and tree7)
		 or (tree0 and tree3 and tree4 and tree6 and tree8)
		 or (tree0 and tree3 and tree4 and tree6 and tree9)
		 or (tree0 and tree3 and tree4 and tree7 and tree8)
		 or (tree0 and tree3 and tree4 and tree7 and tree9)
		 or (tree0 and tree3 and tree4 and tree8 and tree9)
		 or (tree0 and tree3 and tree5 and tree6 and tree7)
		 or (tree0 and tree3 and tree5 and tree6 and tree8)
		 or (tree0 and tree3 and tree5 and tree6 and tree9)
		 or (tree0 and tree3 and tree5 and tree7 and tree8)
		 or (tree0 and tree3 and tree5 and tree7 and tree9)
		 or (tree0 and tree3 and tree5 and tree8 and tree9)
		 or (tree0 and tree3 and tree6 and tree7 and tree8)
		 or (tree0 and tree3 and tree6 and tree7 and tree9)
		 or (tree0 and tree3 and tree6 and tree8 and tree9)
		 or (tree0 and tree3 and tree7 and tree8 and tree9)
		 or (tree0 and tree4 and tree5 and tree6 and tree7)
		 or (tree0 and tree4 and tree5 and tree6 and tree8)
		 or (tree0 and tree4 and tree5 and tree6 and tree9)
		 or (tree0 and tree4 and tree5 and tree7 and tree8)
		 or (tree0 and tree4 and tree5 and tree7 and tree9)
		 or (tree0 and tree4 and tree5 and tree8 and tree9)
		 or (tree0 and tree4 and tree6 and tree7 and tree8)
		 or (tree0 and tree4 and tree6 and tree7 and tree9)
		 or (tree0 and tree4 and tree6 and tree8 and tree9)
		 or (tree0 and tree4 and tree7 and tree8 and tree9)
		 or (tree0 and tree5 and tree6 and tree7 and tree8)
		 or (tree0 and tree5 and tree6 and tree7 and tree9)
		 or (tree0 and tree5 and tree6 and tree8 and tree9)
		 or (tree0 and tree5 and tree7 and tree8 and tree9)
		 or (tree0 and tree6 and tree7 and tree8 and tree9)
		 or (tree1 and tree2 and tree3 and tree4 and tree5)
		 or (tree1 and tree2 and tree3 and tree4 and tree6)
		 or (tree1 and tree2 and tree3 and tree4 and tree7)
		 or (tree1 and tree2 and tree3 and tree4 and tree8)
		 or (tree1 and tree2 and tree3 and tree4 and tree9)
		 or (tree1 and tree2 and tree3 and tree5 and tree6)
		 or (tree1 and tree2 and tree3 and tree5 and tree7)
		 or (tree1 and tree2 and tree3 and tree5 and tree8)
		 or (tree1 and tree2 and tree3 and tree5 and tree9)
		 or (tree1 and tree2 and tree3 and tree6 and tree7)
		 or (tree1 and tree2 and tree3 and tree6 and tree8)
		 or (tree1 and tree2 and tree3 and tree6 and tree9)
		 or (tree1 and tree2 and tree3 and tree7 and tree8)
		 or (tree1 and tree2 and tree3 and tree7 and tree9)
		 or (tree1 and tree2 and tree3 and tree8 and tree9)
		 or (tree1 and tree2 and tree4 and tree5 and tree6)
		 or (tree1 and tree2 and tree4 and tree5 and tree7)
		 or (tree1 and tree2 and tree4 and tree5 and tree8)
		 or (tree1 and tree2 and tree4 and tree5 and tree9)
		 or (tree1 and tree2 and tree4 and tree6 and tree7)
		 or (tree1 and tree2 and tree4 and tree6 and tree8)
		 or (tree1 and tree2 and tree4 and tree6 and tree9)
		 or (tree1 and tree2 and tree4 and tree7 and tree8)
		 or (tree1 and tree2 and tree4 and tree7 and tree9)
		 or (tree1 and tree2 and tree4 and tree8 and tree9)
		 or (tree1 and tree2 and tree5 and tree6 and tree7)
		 or (tree1 and tree2 and tree5 and tree6 and tree8)
		 or (tree1 and tree2 and tree5 and tree6 and tree9)
		 or (tree1 and tree2 and tree5 and tree7 and tree8)
		 or (tree1 and tree2 and tree5 and tree7 and tree9)
		 or (tree1 and tree2 and tree5 and tree8 and tree9)
		 or (tree1 and tree2 and tree6 and tree7 and tree8)
		 or (tree1 and tree2 and tree6 and tree7 and tree9)
		 or (tree1 and tree2 and tree6 and tree8 and tree9)
		 or (tree1 and tree2 and tree7 and tree8 and tree9)
		 or (tree1 and tree3 and tree4 and tree5 and tree6)
		 or (tree1 and tree3 and tree4 and tree5 and tree7)
		 or (tree1 and tree3 and tree4 and tree5 and tree8)
		 or (tree1 and tree3 and tree4 and tree5 and tree9)
		 or (tree1 and tree3 and tree4 and tree6 and tree7)
		 or (tree1 and tree3 and tree4 and tree6 and tree8)
		 or (tree1 and tree3 and tree4 and tree6 and tree9)
		 or (tree1 and tree3 and tree4 and tree7 and tree8)
		 or (tree1 and tree3 and tree4 and tree7 and tree9)
		 or (tree1 and tree3 and tree4 and tree8 and tree9)
		 or (tree1 and tree3 and tree5 and tree6 and tree7)
		 or (tree1 and tree3 and tree5 and tree6 and tree8)
		 or (tree1 and tree3 and tree5 and tree6 and tree9)
		 or (tree1 and tree3 and tree5 and tree7 and tree8)
		 or (tree1 and tree3 and tree5 and tree7 and tree9)
		 or (tree1 and tree3 and tree5 and tree8 and tree9)
		 or (tree1 and tree3 and tree6 and tree7 and tree8)
		 or (tree1 and tree3 and tree6 and tree7 and tree9)
		 or (tree1 and tree3 and tree6 and tree8 and tree9)
		 or (tree1 and tree3 and tree7 and tree8 and tree9)
		 or (tree1 and tree4 and tree5 and tree6 and tree7)
		 or (tree1 and tree4 and tree5 and tree6 and tree8)
		 or (tree1 and tree4 and tree5 and tree6 and tree9)
		 or (tree1 and tree4 and tree5 and tree7 and tree8)
		 or (tree1 and tree4 and tree5 and tree7 and tree9)
		 or (tree1 and tree4 and tree5 and tree8 and tree9)
		 or (tree1 and tree4 and tree6 and tree7 and tree8)
		 or (tree1 and tree4 and tree6 and tree7 and tree9)
		 or (tree1 and tree4 and tree6 and tree8 and tree9)
		 or (tree1 and tree4 and tree7 and tree8 and tree9)
		 or (tree1 and tree5 and tree6 and tree7 and tree8)
		 or (tree1 and tree5 and tree6 and tree7 and tree9)
		 or (tree1 and tree5 and tree6 and tree8 and tree9)
		 or (tree1 and tree5 and tree7 and tree8 and tree9)
		 or (tree1 and tree6 and tree7 and tree8 and tree9)
		 or (tree2 and tree3 and tree4 and tree5 and tree6)
		 or (tree2 and tree3 and tree4 and tree5 and tree7)
		 or (tree2 and tree3 and tree4 and tree5 and tree8)
		 or (tree2 and tree3 and tree4 and tree5 and tree9)
		 or (tree2 and tree3 and tree4 and tree6 and tree7)
		 or (tree2 and tree3 and tree4 and tree6 and tree8)
		 or (tree2 and tree3 and tree4 and tree6 and tree9)
		 or (tree2 and tree3 and tree4 and tree7 and tree8)
		 or (tree2 and tree3 and tree4 and tree7 and tree9)
		 or (tree2 and tree3 and tree4 and tree8 and tree9)
		 or (tree2 and tree3 and tree5 and tree6 and tree7)
		 or (tree2 and tree3 and tree5 and tree6 and tree8)
		 or (tree2 and tree3 and tree5 and tree6 and tree9)
		 or (tree2 and tree3 and tree5 and tree7 and tree8)
		 or (tree2 and tree3 and tree5 and tree7 and tree9)
		 or (tree2 and tree3 and tree5 and tree8 and tree9)
		 or (tree2 and tree3 and tree6 and tree7 and tree8)
		 or (tree2 and tree3 and tree6 and tree7 and tree9)
		 or (tree2 and tree3 and tree6 and tree8 and tree9)
		 or (tree2 and tree3 and tree7 and tree8 and tree9)
		 or (tree2 and tree4 and tree5 and tree6 and tree7)
		 or (tree2 and tree4 and tree5 and tree6 and tree8)
		 or (tree2 and tree4 and tree5 and tree6 and tree9)
		 or (tree2 and tree4 and tree5 and tree7 and tree8)
		 or (tree2 and tree4 and tree5 and tree7 and tree9)
		 or (tree2 and tree4 and tree5 and tree8 and tree9)
		 or (tree2 and tree4 and tree6 and tree7 and tree8)
		 or (tree2 and tree4 and tree6 and tree7 and tree9)
		 or (tree2 and tree4 and tree6 and tree8 and tree9)
		 or (tree2 and tree4 and tree7 and tree8 and tree9)
		 or (tree2 and tree5 and tree6 and tree7 and tree8)
		 or (tree2 and tree5 and tree6 and tree7 and tree9)
		 or (tree2 and tree5 and tree6 and tree8 and tree9)
		 or (tree2 and tree5 and tree7 and tree8 and tree9)
		 or (tree2 and tree6 and tree7 and tree8 and tree9)
		 or (tree3 and tree4 and tree5 and tree6 and tree7)
		 or (tree3 and tree4 and tree5 and tree6 and tree8)
		 or (tree3 and tree4 and tree5 and tree6 and tree9)
		 or (tree3 and tree4 and tree5 and tree7 and tree8)
		 or (tree3 and tree4 and tree5 and tree7 and tree9)
		 or (tree3 and tree4 and tree5 and tree8 and tree9)
		 or (tree3 and tree4 and tree6 and tree7 and tree8)
		 or (tree3 and tree4 and tree6 and tree7 and tree9)
		 or (tree3 and tree4 and tree6 and tree8 and tree9)
		 or (tree3 and tree4 and tree7 and tree8 and tree9)
		 or (tree3 and tree5 and tree6 and tree7 and tree8)
		 or (tree3 and tree5 and tree6 and tree7 and tree9)
		 or (tree3 and tree5 and tree6 and tree8 and tree9)
		 or (tree3 and tree5 and tree7 and tree8 and tree9)
		 or (tree3 and tree6 and tree7 and tree8 and tree9)
		 or (tree4 and tree5 and tree6 and tree7 and tree8)
		 or (tree4 and tree5 and tree6 and tree7 and tree9)
		 or (tree4 and tree5 and tree6 and tree8 and tree9)
		 or (tree4 and tree5 and tree7 and tree8 and tree9)
		 or (tree4 and tree6 and tree7 and tree8 and tree9)
		 or (tree5 and tree6 and tree7 and tree8 and tree9)
}
    