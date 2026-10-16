// Example rule for your own SecCorp database (YARA-compatible subset).
// Detects the harmless marker file signatures/samples/custom-test.txt.

rule SecCorp_Custom_Test_Marker : test
{
    meta:
        threat = "SecCorp-Custom-Test"
        description = "Harmless marker file: checks that a custom signature database is loaded."
        severity = "low"
    strings:
        $marker = "SECCOM-CUSTOM-SIGNATURE-TEST-7b3f9a"
    condition:
        $marker at 0 and filesize < 1KB
}
