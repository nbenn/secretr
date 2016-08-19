#include <R.h>
#include <Rinternals.h>

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

static void ShowErrorMessage(OSStatus status) {
  CFStringRef error_msg = SecCopyErrorMessageString(status, NULL);
  if (error_msg == NULL) {
    Rf_warning("Error message is NULL.");
  } else {
    CFIndex length = CFStringGetLength(error_msg);
    CFIndex max_size = CFStringGetMaximumSizeForEncoding(length,
      kCFStringEncodingUTF8) + 1;
    char *error_str = (char *)malloc(max_size);
    Boolean success;
    success = CFStringGetCString(error_msg, error_str, max_size,
      kCFStringEncodingUTF8);
    if (success) {
      Rf_warning("Encountered error: %s (Code %d).", error_str, (int)status);
    } else {
      Rf_warning("Could not get string from error message.");
    }
    free(error_str);
  }
  CFRelease(error_msg);
}

static int CountGenericPasswordServiceNameMatches(const char *serviceName) {
  OSStatus result;
  CFTypeRef results = NULL;
  CFDictionaryRef query = NULL;
  const void *keys[3], *values[3];

  keys[0]   = kSecClass;
  values[0] = kSecClassGenericPassword;
  keys[1]   = kSecAttrService;
  values[1] = CFStringCreateWithCStringNoCopy(NULL, serviceName,
    kCFStringEncodingUTF8, kCFAllocatorNull);
  keys[2]   = kSecMatchLimit;
  values[2] = kSecMatchLimitAll;

  query = CFDictionaryCreate(NULL, keys, values, 3,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  result = SecItemCopyMatching(query, &results);
  CFRelease(query);

  if (result == errSecItemNotFound) {
    return 0;
  } else if (result == errSecSuccess) {
    int matches = CFArrayGetCount(results);
    CFRelease(results);
    return matches;
  } else {
    ShowErrorMessage(result);
    return -1;
  }
}

const char* GetGenericPasswordUserName(const char *serviceName) {
  OSStatus status;
  CFTypeRef results = NULL;
  CFDictionaryRef query = NULL;
  const void *keys[3], *values[3];
  CFStringRef username;
  CFIndex username_length;
  char *username_str;
  Boolean success;

  int match_count = CountGenericPasswordServiceNameMatches(serviceName);
  if (match_count != 1) {
    Rf_error("Did not find 1, but %i matches.", match_count);
  }

  keys[0]   = kSecClass;
  values[0] = kSecClassGenericPassword;
  keys[1]   = kSecAttrService;
  values[1] = CFStringCreateWithCStringNoCopy(NULL, serviceName,
    kCFStringEncodingUTF8, kCFAllocatorNull);
  keys[2]   = kSecReturnAttributes;
  values[2] = kCFBooleanTrue;

  query = CFDictionaryCreate(NULL, keys, values, 3,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  status = SecItemCopyMatching(query, &results);
  CFRelease(query);

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    return NULL;
  }

  username = CFDictionaryGetValue(results, CFSTR("acct"));
  username_length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(
    username), kCFStringEncodingUTF8) + 1;
  username_str = (char *)malloc(username_length);
  success = CFStringGetCString(username, username_str, username_length, kCFStringEncodingUTF8);

  CFRelease(username);

  if (success) return username_str;
  else return NULL;
}

SEXP storeLoginItemKeychain_(SEXP service_, SEXP username_, SEXP password_) {
  const char *srv, *usr, *pwd;
  int match_count;
  OSStatus status;

  if (TYPEOF(service_) != STRSXP || LENGTH(service_) != 1) {
    Rf_error("Invalid service name.");
  }
  if (TYPEOF(username_) != STRSXP || LENGTH(username_) != 1) {
    Rf_error("Invalid user name.");
  }
  if (TYPEOF(password_) != STRSXP || LENGTH(password_) != 1) {
    Rf_error("Invalid password.");
  }

  srv = Rf_translateCharUTF8(STRING_ELT(service_, 0));
  usr = Rf_translateCharUTF8(STRING_ELT(username_, 0));
  pwd = Rf_translateCharUTF8(STRING_ELT(password_, 0));

  match_count = CountGenericPasswordServiceNameMatches(srv);
  if (match_count > 0) {
    Rf_error("The item to be stored is already present.");
  } else if (match_count < 0) {
    Rf_error("Error determining whether item is already present.");
  }

  status = SecKeychainAddGenericPassword (
             NULL,        // default keychain
             strlen(srv), // length of service name
             srv,         // service name
             strlen(usr), // length of account name
             usr,         // account name
             strlen(pwd), // length of password
             pwd,         // pointer to password data
             NULL         // the item reference
  );

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    Rf_error("Error storing the item.");
  }

  return R_NilValue;
}

SEXP updateLoginItemKeychain_(SEXP service_, SEXP username_, SEXP password_) {
  const char *srv;
  const char *new_usr, *old_usr;
  const char *new_pwd;
  OSStatus status;
  SecKeychainItemRef item;

  if (TYPEOF(service_) != STRSXP || LENGTH(service_) != 1) {
    Rf_error("Invalid service name.");
  }
  if (TYPEOF(username_) != STRSXP || LENGTH(username_) != 1) {
    Rf_error("Invalid user name.");
  }
  if (TYPEOF(password_) != STRSXP || LENGTH(password_) != 1) {
    Rf_error("Invalid password.");
  }

  srv     = Rf_translateCharUTF8(STRING_ELT(service_, 0));
  new_usr = Rf_translateCharUTF8(STRING_ELT(username_, 0));
  new_pwd = Rf_translateCharUTF8(STRING_ELT(password_, 0));
  old_usr = GetGenericPasswordUserName(srv);

  if (old_usr == NULL) {
    Rf_error("Error determining the associated username.");
  }

  status = SecKeychainFindGenericPassword (
             NULL,            // default keychain
             strlen(srv),     // length of service name
             srv,             // service name
             strlen(old_usr), // length of account name
             old_usr,         // account name
             0,               // length of password
             NULL,            // pointer to password data
             &item            // the item reference
  );

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    Rf_error("Error finding the requested item.");
  }

  SecKeychainAttribute attrs[1];
  attrs[0].tag = kSecAccountItemAttr;
  attrs[0].length = strlen(new_usr);
  attrs[0].data = (void *)new_usr;
  SecKeychainAttributeList attrList = { 1, attrs };

  status = SecKeychainItemModifyContent (
             item,            // the item reference
             &attrList,       // list of attributes to be modified
             strlen(new_pwd), // length of password
             new_pwd          // pointer to password data
  );

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    Rf_error("Error updating the requested item.");
  }

  free((char*)old_usr);
  CFRelease(item);

  return R_NilValue;
}

SEXP fetchLoginItemKeychain_(SEXP service_) {
  const char *srv;
  const char *usr;
  void *pwd;
  UInt32 pwd_len = 0;
  OSStatus status;

  if (TYPEOF(service_) != STRSXP || LENGTH(service_) != 1) {
    Rf_error("Invalid service name.");
  }
  srv = Rf_translateCharUTF8(STRING_ELT(service_, 0));
  usr = GetGenericPasswordUserName(srv);

  if (usr == NULL) {
    Rf_error("Error determining the associated username.");
  }

  status = SecKeychainFindGenericPassword (
             NULL,        // default keychain
             strlen(srv), // length of service name
             srv,         // service name
             strlen(usr), // length of account name
             usr,         // account name
             &pwd_len,    // length of password
             &pwd,        // pointer to password data
             NULL         // the item reference
  );

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    Rf_error("Could not complete your request.");
  }

  const char *names[] = {"username", "password", ""};
  SEXP result_ = PROTECT(mkNamed(VECSXP, names));
  SET_VECTOR_ELT(result_, 0, Rf_ScalarString(Rf_mkCharLenCE(usr, strlen(usr),
    CE_UTF8)));
  SET_VECTOR_ELT(result_, 1, Rf_ScalarString(Rf_mkCharLenCE(pwd, pwd_len,
    CE_UTF8)));
  SecKeychainItemFreeContent(NULL, pwd);
  free((char*)usr);
  UNPROTECT(1);
  return result_;
}

SEXP removeLoginItemKeychain_(SEXP service_) {
  const char *srv;
  const char *usr;
  OSStatus status;
  SecKeychainItemRef item;
  void *pwd;
  UInt32 pwd_len = 0;

  if (TYPEOF(service_) != STRSXP || LENGTH(service_) != 1) {
    Rf_error("Invalid service name.");
  }
  srv = Rf_translateCharUTF8(STRING_ELT(service_, 0));
  usr = GetGenericPasswordUserName(srv);

  if (usr == NULL) {
    Rf_error("Error determining the associated username.");
  }

  // only retrieve password to make sure the user has access rights
  status = SecKeychainFindGenericPassword (
             NULL,        // default keychain
             strlen(srv), // length of service name
             srv,         // service name
             strlen(usr), // length of account name
             usr,         // account name
             &pwd_len,    // length of password
             &pwd,        // pointer to password data
             &item        // the item reference
  );

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    Rf_error("Error finding the requested item.");
  }

  SecKeychainItemFreeContent(NULL, pwd);
  status = SecKeychainItemDelete(item);

  if (status != errSecSuccess) {
    ShowErrorMessage(status);
    Rf_error("Error deleting the requested item.");
  }

  CFRelease(item);
  return R_NilValue;
}

#else

static void ShowErrorMessage() {
  Rf_error("Keychain services are only available under Mac OS >= 10.6.");
}

SEXP storeLoginItemKeychain_(SEXP service_, SEXP username_, SEXP password_) {
  ShowErrorMessage();
  return R_NilValue;
}

SEXP updateLoginItemKeychain_(SEXP service_, SEXP username_, SEXP password_) {
  ShowErrorMessage();
  return R_NilValue;
}

SEXP fetchLoginItemKeychain_(SEXP service_) {
  ShowErrorMessage();
  return R_NilValue;
}

SEXP removeLoginItemKeychain_(SEXP service_) {
  ShowErrorMessage();
  return R_NilValue;
}

#endif
