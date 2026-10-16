package sbs.astrogate.mail.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ChecksTest {
    @Test void adminPasswordMayUseNineCharactersWithoutRelaxingMailboxPasswords() {
        assertEquals("123456789", Checks.adminPassword("123456789"));
        assertThrows(IllegalArgumentException.class, () -> Checks.adminPassword("12345678"));
        assertThrows(IllegalArgumentException.class, () -> Checks.password("123456789"));
        assertEquals("a-long-mailbox-password", Checks.password("a-long-mailbox-password"));
    }

    @Test void bothPasswordPoliciesEnforceBcryptByteLimitAndRejectControlCharacters() {
        String tooLong="a".repeat(73);
        assertThrows(IllegalArgumentException.class, () -> Checks.adminPassword(tooLong));
        assertThrows(IllegalArgumentException.class, () -> Checks.password(tooLong));
        assertThrows(IllegalArgumentException.class, () -> Checks.adminPassword("12345678\n"));
    }
}
