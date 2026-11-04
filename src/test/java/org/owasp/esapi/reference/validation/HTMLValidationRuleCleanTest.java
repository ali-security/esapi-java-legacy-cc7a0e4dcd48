/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2019 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author kevin.w.wall@gmail.com
 * @since 2019
 */
package org.owasp.esapi.reference.validation;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperRequest;
import org.owasp.esapi.reference.validation.HTMLValidationRule;
import static org.owasp.esapi.PropNames.VALIDATOR_HTML_VALIDATION_ACTION;

import org.junit.Test;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.After;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import static org.hamcrest.CoreMatchers.both;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The Class HTMLValidationRuleCleanTest.
 *
 * Based on original test cases, testGetValidSafeHTML() and
 * testIsValidSafeHTML() from ValidatorTest by
 *      Mike Fauzy (mike.fauzy@aspectsecurity.com) and
 *      Jeff Williams (jeff.williams@aspectsecurity.com)
 * that were originally part of src/test/java/org/owasp/esapi/reference/ValidatorTest.java.
 *
 * This class tests the cases where the new ESAPI.property
 *      Validator.HtmlValidationAction
 * is set to "clean", which causes certain calls to
 * ESAPI.validator().getValidSafeHTML() or ESAPI.validator().isValidSafeHTML()
 * to simply log a warning and return the cleansed (sanitized) output rather
 * than throwing a ValidationException when certain unsafe input is
 * encountered.
 * 
 * @author kevin.w.wall@gmail.com
 */
public class HTMLValidationRuleCleanTest {
	private static SecurityConfiguration origConfig = ESAPI.securityConfiguration();

    private static class ConfOverride extends SecurityConfigurationWrapper {
        private String desiredReturn = "clean";

        ConfOverride(SecurityConfiguration orig, String desiredReturn) {
            super(orig);
            this.desiredReturn = desiredReturn;
        }

        @Override
        public String getStringProp(String propName) {
            // Would it be better making this file a static import?
            if ( propName.equals( VALIDATOR_HTML_VALIDATION_ACTION ) ) {
                return desiredReturn;
            } else {
                return super.getStringProp( propName );
            }
        }
    }


    /**
     * Default constructor that instantiates a new {@code HTMLValidationRule} test.
     */
    public HTMLValidationRuleCleanTest() {
    }

    @After
    public void tearDown() throws Exception {
        ESAPI.override(null);
    }

    @Before
    public void setUp() throws Exception {
        ESAPI.override(
            new ConfOverride( origConfig, "clean" )
        );

    }

    @Test
    public void testGetValidSafeHTML() throws Exception {
        System.out.println("testGetValidSafeHTML");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();

        HTMLValidationRule rule = new HTMLValidationRule("test");
        ESAPI.validator().addRule(rule);

        assertEquals("Test.", ESAPI.validator().getRule("test").getValid("test", "Test. <script>alert(document.cookie)</script>"));

        String test1 = "<b>Jeff</b>";
        String result1 = instance.getValidSafeHTML("test", test1, 100, false, errors);
        assertEquals(test1, result1);

        String test2 = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>";
        String result2 = instance.getValidSafeHTML("test", test2, 100, false, errors);
        assertEquals(test2, result2);

        String test3 = "Test. <script>alert(document.cookie)</script> Cookie :-)";
        assertEquals("Test.  Cookie :-)", rule.getSafe("test", test3));

        assertEquals("Test. &lt;<div>load=alert()</div>", rule.getSafe("test", "Test. <<div on<script></script>load=alert()"));
        assertEquals("Test. <div>b</div>", rule.getSafe("test", "Test. <div style={xss:expression(xss)}>b</div>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s%00cript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
    }

    // Test to confirm that CVE-2022-24891 is fixed in ESAPI. The cause of this was
    // from a subtly botched regex for 'onsiteURL' in all the versions of
    // antsamy-esapi.xml that had been there as far back as ESAPI 1.4!
    //
    // This CVE should arguably get the same CVSSv3 score as the AntiSamy
    // CVE-2021-35043 as they are very similar.
    //
    // Updated: Requested CVE from GitHub CNA on 4/23/2022. See also
    // https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-q77q-vx4q-xx6q
    @Test
    public void testESAPI_CVE_2022_24891() throws Exception {
        System.out.println("testESAPI_CVE_2022_24891");

        String expectedSafeText = "This is safe from XSS. Trust us!";
        String badVoodoo = "<a href=\"javascript:alert(1)\">" + expectedSafeText + "</a>";
        Validator instance = ESAPI.validator();
        ValidationErrorList errorList = new ValidationErrorList();
        String result = instance.getValidSafeHTML("test", badVoodoo, 100, false, errorList);
        assertEquals( expectedSafeText, result );
    }

    // To confirm fix for CVE-2021-35043 in AntiSamy 1.6.5 and later. Actually,
    // it was never really "broken" in ESAPI's "default configuration" because it is
    // triggers an Intrusion Detection when it is checking the canonicalization
    // and the '&#00058' trips it up, that that's pretty much irrelevant given
    // the CVE mentioned in the previous test case.
    //
    // Note: This test assumes a standard default ESAPI.properties file. In
    // particular, the normal canonicalization has to be enabled.
    //
    public void testAntiSamy_CVE_2021_35043Fixed() throws Exception {
        System.out.println("testAntiSamy_CVE_2021_35043Fixed");

        String expectedSafeText = "This is safe from XSS. Trust us!";

            // Translates to '<a href="javascript:x=1,alert("boom")".
        String badVoodoo = "<a href=\"javascript&#00058alert(1)>" + expectedSafeText + "</a>";
        Validator instance = ESAPI.validator();
        String cleansed = instance.getValidSafeHTML("CVE-2021-35043", badVoodoo, 200, false);
        assertEquals( "", cleansed );
    }

    ////////// New AntiSamy tests added to ESAPI 2.5.3.0 //////////
    // Some of these were with the new XSS discoveries in AntiSamy.
    // Sebastian doesn't think thta ESAPI should be vulnerable to these 2. (They weren't.)
    @Test
    public void testQuotesInsideStyles() throws Exception {
    	System.out.println("testQuotesInsideStyles");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();

        // Added this test because of a fix to AntiSamy that doesn't seem to have affected ESAPI because of our
        // very restrictive default AntiSamy policy file. However, with some of AntiSamy policy files, this used
        // to cause any quoted (double or single) string identifier in CSS was being enclosed in quotes.
        // That resulted in quotes enclosed by more quotes in some cases without any kind of escape or
        // transformation. It never did that for ESAPI, but it seemed like a good test to add.
        String input =
            "<span style=\"font-family: 'comic sans ms', sans-serif; color: #ba372a;\">Safe Text</span>";
        String expected = "Safe Text";  // We expect the span tag to be completely filtered out & only the tag contents to remain.
        String output = instance.getValidSafeHTML("testQuotesInsideStyles-1", input, 250, false);
        assertEquals(expected, output);

        input = "<span style='font-family: \"comic sans ms\", sans-serif; color: #ba372a;'>Safe Text</span>"; // Slight variation
        output = instance.getValidSafeHTML("testQuotesInsideStyle-2", input, 250, false);
        assertEquals(expected, output);

        assertTrue(errors.size() == 0);
    }

    @Test
    public void testSmuggledTagsInStyleContentCase() throws Exception {
    	System.out.println("testSmuggledTagsInStyleContentCase");

        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();

        // Style tag processing was not handling correctly the value set to its child node that should
        // be only text. On some mutation scenarios due to filtering tags by default, content was being
        // smuggled and not properly sanitized by the output serializer.
        //
        // Not expected to affect ESAPI because our default AntiSamy policy file does NOT have:
        //          <tag name="style" action="validate">
        // in it.
        //
        String input = "Safe<style/><listing/>]]><noembed></style><img src=x onerror=mxss(1)></noembed> stuff";
        String output = null;
        String expected = null;
        try {
            expected = "Safe&lt;listing/&gt;]]&gt;&lt;noembed&gt; stuff";
            output = instance.getValidSafeHTML("testSmuggledTagsInStyleContentCase-1", input, 250, false, errors);
        } catch (IntrusionException ex) {
            fail("testSmuggledTagsInStyleContentCase-1 - should not happen.");
        }
        assertTrue(errors.size() == 0);
        assertEquals(expected, output);

        input = "Safe<style/><math>'<noframes ></style><img src=x onerror=mxss(1)></noframes>' stuff";
        try {
            expected = "Safe&lt;math&gt;'&lt;noframes &gt;' stuff";
            output = instance.getValidSafeHTML("testSmuggledTagsInStyleContentCase-2", input, 250, false, errors);
        } catch (IntrusionException ex) {
            fail("testSmuggledTagsInStyleContentCase-2 - should not happen.");
        }
        assertTrue(errors.size() == 0);
        assertEquals(expected, output);
    }

    @Test
    public void testAntiSamy_CVE_2023_43643() {
      System.out.println("testAntiSamy_CVE_2023_43643");
      // These are new tests are variations from AntiSamy 1.7.4 and were associted with CVE-2023-43643. (See
      // https://github.com/nahsra/antisamy/security/advisories/GHSA-pcf2-gh6g-h5r2 for additional details.)
      // The concern is that when preserving comments, certain tags would get their content badly parsed
      // due to mutation XSS. Note that AntiSamy 1.7.3 and earlier had problems (depending on it's
      // AntiSamy policy file) for all these constructs, but ESAPI using AntiSamy 1.7.3 had no vulnerabilities
      // because our antisamy-esapi.xml AntiSamy policy file is much stricter. Regardless, these make good
      // additions to our test suite.
      String[] payloads = {
        "<noscript><!--</noscript><img src=x onerror=mxss(1)>-->",
        "<textarea/><!--</textarea><img src=x onerror=mxss(1)>-->",
            // Note: <xmp> is a deprecated tag, but some browsers may still support.
        "<xmp/><!--</xmp><img src=x onerror=mxss(1)>-->"
      };
  
      Validator instance = ESAPI.validator();
      int testCase = 0;
      for (String payload : payloads) {
          String testId = "";
          try {
              testId = "testAntiSamy_CVE_2023_43643- " + testCase++;
              String output = instance.getValidSafeHTML(testId, payload, 250, false);
              assertThat(testId + ": payload not cleansed from JS mxss()...", output, not(containsString("mxss")));
          } catch( ValidationException vex ) {
              fail(testId + " caused ValidationException: " + vex);
          }
      }
    }
    ////////////////////////////////////////

    /**
     * @deprecated because Validator.isValidSafeHTML is deprecated.
     * @see org.owasp.esapi.Validator#isValidSafeHTML(String,String,int,boolean)
     * @see org.owasp.esapi.Validator#isValidSafeHTML(String,String,int,boolean,org.owasp.esapi.ValidationErrorList)
     */
    //
    // GHSA-r68h-jhhj-9jvm: In "clean" mode, Validator.isValidSafeHTML() used to
    // return true for unsafe input because AntiSamy merely sanitized it (and only
    // logged the scan errors), even though callers then go on to use the original,
    // unsanitized input. It now fails closed: it returns true only if AntiSamy
    // reports no scan errors and the sanitized HTML equals the input exactly.
    @Deprecated
    @Test
    public void testIsValidSafeHTML() {
        System.out.println("testIsValidSafeHTML");
        Validator instance = ESAPI.validator();

        assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

        ValidationErrorList errors = new ValidationErrorList();
        assertTrue(instance.isValidSafeHTML("test1", "<b>Jeff</b>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test2", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false, errors));
        assertTrue(errors.size() == 0);
        assertFalse(instance.isValidSafeHTML("test3", "Test. <script>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test4", "Test. <div style={xss:expression(xss)}>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test5", "Test. <s%00cript>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test6", "Test. <s\tcript>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test7", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(errors.size() == 5);

        // Extracted from testIEConditionalComment().
        errors = new ValidationErrorList();
        String input = "<!--[if gte IE 4]>\r\n <SCRIPT>alert('XSS');</SCRIPT>\r\n<![endif]-->";
        assertFalse(instance.isValidSafeHTML("test12", input, 100, false)); // Not safe bc sanitizing changes it to "".
        assertFalse(instance.isValidSafeHTML("test12", input, 100, false, errors));
        assertTrue(errors.size() == 1);

        // Extracted from testNekoDOSWithAnHTMLComment()
        errors = new ValidationErrorList();
        input = "<!--><?a/";
        assertFalse(instance.isValidSafeHTML("test11", input, 100, false, errors)); // Not safe bc sanitizing changes it to "".
        assertTrue(errors.size() == 1);

        // Extracted from testESAPI_CVE_2022_24891()
        String expectedSafeText = "This is safe from XSS. Trust us!";
        String badVoodoo = "<a href=\"javascript&#00058alert(1)>" + expectedSafeText + "</a>";
        boolean result = instance.isValidSafeHTML("CVE-2021-35043", badVoodoo, 200, false);
        assertFalse( result );
    }

    // GHSA-r68h-jhhj-9jvm: Even though Validator.HtmlValidationAction is "clean"
    // (so getValidSafeHTML() only logs the AntiSamy scan errors and returns the
    // sanitized output), isValidSafeHTML() must treat AntiSamy scan errors as a
    // failure and record that ValidationException in the error list.
    @Deprecated
    @Test
    public void testIsValidSafeHTMLFailsOnScanErrorsInCleanMode() throws Exception {
        System.out.println("testIsValidSafeHTMLFailsOnScanErrorsInCleanMode");
        Validator instance = ESAPI.validator();

        String input = "Test. <script>alert(document.cookie)</script>";
        // In "clean" mode, this does not throw; it silently strips the script.
        String sanitized = instance.getValidSafeHTML("scanErrors-get", input, 100, false);
        assertThat(sanitized, not(containsString("script")));

        ValidationErrorList errors = new ValidationErrorList();
        assertFalse(instance.isValidSafeHTML("scanErrors", input, 100, false, errors));
        assertEquals(1, errors.size());
        ValidationException vex = errors.getError("scanErrors");
        assertNotNull(vex);
        assertEquals("scanErrors: Invalid HTML input", vex.getUserMessage());
        // The AntiSamy scan errors themselves are what was detected, not merely the altered output.
        assertThat(vex.getLogMessage(), containsString("does not follow rules"));

        // Exceptions (here, input longer than maxLength) are also reported as not valid.
        errors = new ValidationErrorList();
        assertFalse(instance.isValidSafeHTML("tooLong", "<b>Jeff</b>", 5, false));
        assertFalse(instance.isValidSafeHTML("tooLong", "<b>Jeff</b>", 5, false, errors));
        assertEquals(1, errors.size());

        // Null / empty input is still valid when (and only when) allowNull is true.
        errors = new ValidationErrorList();
        assertTrue(instance.isValidSafeHTML("empty1", "", 100, true));
        assertTrue(instance.isValidSafeHTML("empty2", null, 100, true, errors));
        assertTrue(errors.isEmpty());
        assertFalse(instance.isValidSafeHTML("empty3", "", 100, false));
        assertFalse(instance.isValidSafeHTML("empty4", null, 100, false, errors));
        assertEquals(1, errors.size());
    }

    // GHSA-r68h-jhhj-9jvm: Input that is canonicalized (decoded) before being
    // scanned, or otherwise altered by sanitization, is never reported as valid,
    // because the caller would otherwise go on to use the original, unsanitized input.
    @Deprecated
    @Test
    public void testIsValidSafeHTMLFailsWhenSanitizingAltersInput() throws Exception {
        System.out.println("testIsValidSafeHTMLFailsWhenSanitizingAltersInput");
        Validator instance = ESAPI.validator();

        String[] payloads = {
            "<b>Jeff",                                                       // Unclosed tag gets closed.
            "Test. <a href=\"javascript:alert(1)\">click me</a>",            // javascript: URL is dropped.
            "<img src=x onerror=alert(1)>",                                  // Event handler / tag dropped.
            "Test. <b onmouseover=alert(1)>Jeff</b>",                        // Event handler attribute dropped.
            " <b>Jeff</b> "                                                  // Even whitespace changes count.
        };

        int testCase = 0;
        for (String payload : payloads) {
            String testId = "altered-" + testCase++;
            ValidationErrorList errors = new ValidationErrorList();
            String sanitized = instance.getValidSafeHTML(testId + "-get", payload, 100, false, errors);
            assertThat(testId + ": expected sanitizing to alter the payload", sanitized, not(equalTo(payload)));
            assertFalse(testId + ": payload should not be valid", instance.isValidSafeHTML(testId, payload, 100, false));
            assertFalse(testId + ": payload should not be valid", instance.isValidSafeHTML(testId, payload, 100, false, errors));
            assertNotNull(testId + ": expected a recorded ValidationException", errors.getError(testId));
        }
    }

    // This test has been significantly changed because as on AntiSamy 1.7.4
    // (first used with ESAPI 2.5.3.0) has changed the results of
    // Validator.getValidSafeHTMLfor this output. Prior to AntiSamy 1.7.4, the
    // expected output was:
    //      b&lt;/style&gt;&lt;a href=javascript:alert(1)&gt;test
    // but with AntiSamy 1.7.4, it now is:
    //      b&lt;![cdata[test
    // which is still safe, but as a result, this test had to change.
    //
    // See AntiSamy GitHub issue #380 (https://github.com/nahsra/antisamy/issues/389) for more details.
    //
    // Also, this test, which originally used Validator.isValidSafeHTML(), has been
    // changed to use Validator.getValidSafeHTML() instead because Validator.isValidSafeHTML()
    // has been deprecated. See GitHub Security Advisory
    // https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-r68h-jhhj-9jvm
    // and the referenced ESAPI Security Bulletin mentioned therein.
    @Test
    public void testAntiSamyRegressionCDATAWithJavascriptURL() throws Exception {
    	System.out.println("testAntiSamyRegressionCDATAWithJavascriptURL");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<style/>b<![cdata[</style><a href=javascript:alert(1)>test";
        // String expected = "b&lt;script&gt;alert(1)&lt;/script&gt;";      // Before AntiSamy 1.7.4
        String expected = "b&lt;![cdata[test";                              // AntiSamy 1.7.4 (and later?)
        String output = instance.getValidSafeHTML("javascript Link", input, 250, false, errors);
        assertEquals(expected, output);
        assertTrue(errors.size() == 0);
    }

    // This test has been significantly changed because as on AntiSamy 1.7.4
    // (first used with ESAPI 2.5.3.0) has changed the results of
    // Validator.getValidSafeHTMLfor this output. Prior to AntiSamy 1.7.4, the
    // expected output was:
    //      W&lt;script&gt;alert(1)&lt;/script&gt;
    // but with AntiSamy 1.7.4, it now is:
    //      W&lt;xmp&lt;script&gt;alert(1)&lt;/script&gt;
    // which is still safe, but as a result, this test had to change.
    //
    // See AntiSamy GitHub issue #380 (https://github.com/nahsra/antisamy/issues/389) for more details.
    //
    // The output has changed again as of AntiSamy 1.7.5. The expected output is now:
    //      Walert(1)
    // See AntiSamy Release notes for 1.7.5 (https://github.com/nahsra/antisamy/releases/tag/v1.7.5)
    //
    // Also, this test, which originally used Validator.isValidSafeHTML(), has been
    // changed to use Validator.getValidSafeHTML() instead because Validator.isValidSafeHTML()
    // has been deprecated. See GitHub Security Advisory
    // https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-r68h-jhhj-9jvm
    // and the referenced ESAPI Security Bulletin mentioned therein.
    @Test
    public void testScriptTagAfterStyleClosing() throws Exception {
    	System.out.println("testScriptTagAfterStyleClosing");

        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<select<style/>W<xmp<script>alert(1)</script>";
        // String expected = "W&lt;script&gt;alert(1)&lt;/script&gt;";        // Before AntiSamy 1.7.4
        // String expected = "W&lt;xmp&lt;script&gt;alert(1)&lt;/script&gt;";    // AntiSamy 1.7.4
        String expected = "Walert(1)";                                      // AntiSamy 1.7.5 (and later?)
        String output = instance.getValidSafeHTML("escaping style tag attack with script tag", input, 250, false, errors);
        assertEquals(expected, output);
        assertTrue(errors.size() == 0);
    }

    // This test has been significantly changed because as on AntiSamy 1.7.4
    // (first used with ESAPI 2.5.3.0) has changed the results of
    // Validator.getValidSafeHTMLfor this output. Prior to AntiSamy 1.7.4, the
    // expected output was:
    //      k&lt;input/onfocus=alert(1)&gt;
    // but with AntiSamy 1.7.4, it now is:
    //      k&lt;input&lt;&lt;/&gt;input/onfocus=alert(1)&gt;
    // which is still safe, but as a result, this test had to change.
    //
    // See AntiSamy GitHub issue #380 (https://github.com/nahsra/antisamy/issues/389) for more details.
    //
    // The output has changed again as of AntiSamy 1.7.5. The expected output is now:
    //      kinput/onfocus=alert(1)&gt;
    // See AntiSamy Release notes for 1.7.5 (https://github.com/nahsra/antisamy/releases/tag/v1.7.5)
    //
    // Also, this test, which originally used Validator.isValidSafeHTML(), has been
    // changed to use Validator.getValidSafeHTML() instead because Validator.isValidSafeHTML()
    // has been deprecated. See GitHub Security Advisory
    // https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-r68h-jhhj-9jvm
    // and the referenced ESAPI Security Bulletin mentioned therein.
    @Test
    public void testOnfocusAfterStyleClosing() throws Exception {
    	System.out.println("testOnfocusAfterStyleClosing");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<select<style/>k<input<</>input/onfocus=alert(1)>";

        // String expected = "k&lt;input/onfocus=alert(1)&gt;";    // Before AntiSamy 1.7.4
        // String expected = "k&lt;input&lt;&lt;/&gt;input/onfocus=alert(1)&gt;";    // AntiSamy 1.7.4
        String expected = "kinput/onfocus=alert(1)&gt;";    // AntiSamy 1.7.5 (and later?)
        String output = instance.getValidSafeHTML("escaping style tag attack with onfocus attribute", input, 250, false, errors);
        assertEquals(expected, output);
        assertTrue(errors.size() == 0);
    }

    // This test was a DoS issue (CVE-2022-28366) within a transitive dependency (Neko-HtmlUnit) that AntiSamy uses.
    // It is fixed only in Neko-HtmlUnit 2.27 and later, but all those releases are only available for Java 8 and later.
    //
    // When the input here is called with AntiSamy.scan().getCleanHtml(), AntiSamy throws a ScanException.
    // (For details, see the AntiSamy JUnit test case "testMalformedPIScan" in
    // https://github.com/nahsra/antisamy/blob/main/src/test/java/org/owasp/validator/html/test/AntiSamyTest.java.)
    //
    @Test
    public void testNekoDOSWithAnHTMLComment() throws Exception {
        System.out.println("testNekoDOSWithAnHTMLComment");

        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<!--><?a/";
        String expectEmpty = "";
        String output = instance.getValidSafeHTML("escaping style tag attack", input, 250, false);
        assertEquals(expectEmpty, output);  // Because AntiSamy's CleanResults.getCleanHTML() should throw and is caught.
        assertTrue(errors.size() == 0);
    }

    @Test
    public void testIEConditionalComment() throws Exception {
        System.out.println("testIEConditionalComment");

        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<!--[if gte IE 4]>\r\n <SCRIPT>alert('XSS');</SCRIPT>\r\n<![endif]-->";
        String expectEmpty = "";
        String output = instance.getValidSafeHTML("escaping IE conditional comment", input, 250, true);
        assertEquals(expectEmpty, output);  // Expect AntiSamy to return empty string here.
    }
}
