//! Small, type-checked readers for CoreFoundation property-list dictionaries.
//!
//! Several macOS APIs we depend on (`CGSessionCopyCurrentDictionary`,
//! `SCDynamicStoreCopyValue`, `CGWindowListCopyWindowInfo`) return untyped
//! `CFDictionary`/`CFArray` trees. Every value is checked with
//! `CFGetTypeID` (via `downcast_ref`) before use, so a missing key or an
//! unexpected type from the OS yields `None` instead of undefined behaviour.

use objc2_core_foundation::{CFArray, CFBoolean, CFDictionary, CFNumber, CFString, CFType};

/// View an opaque dictionary as `CFString -> CFType`.
pub(crate) fn as_plist_dict(dict: &CFDictionary) -> &CFDictionary<CFString, CFType> {
    // SAFETY: every CoreFoundation object is a `CFType`, so values are valid
    // as `CFType`. Keys are only used for lookups through the dictionary's
    // own equality callbacks (`CFEqual`), which accept any CF object; we never
    // read a key back as a `CFString` without a type check.
    unsafe { dict.cast_unchecked::<CFString, CFType>() }
}

/// View an opaque array as an array of `CFType`.
pub(crate) fn as_type_array(array: &CFArray) -> &CFArray<CFType> {
    // SAFETY: every element of a CFArray created by the OS is a CF object.
    unsafe { array.cast_unchecked::<CFType>() }
}

fn value(
    dict: &CFDictionary<CFString, CFType>,
    key: &str,
) -> Option<objc2_core_foundation::CFRetained<CFType>> {
    dict.get(&CFString::from_str(key))
}

/// Read a boolean value. Accepts `CFBoolean` and, defensively, a `CFNumber`
/// (some plist producers encode flags as 0/1).
pub(crate) fn get_bool(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<bool> {
    let v = value(dict, key)?;
    if let Some(b) = v.downcast_ref::<CFBoolean>() {
        return Some(b.as_bool());
    }
    v.downcast_ref::<CFNumber>()?.as_i64().map(|n| n != 0)
}

pub(crate) fn get_i64(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<i64> {
    value(dict, key)?.downcast_ref::<CFNumber>()?.as_i64()
}

pub(crate) fn get_string(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
    Some(value(dict, key)?.downcast_ref::<CFString>()?.to_string())
}

/// Read a nested dictionary-array value (`[{…}, {…}]`), skipping elements that
/// are not dictionaries.
pub(crate) fn get_dict_array(
    dict: &CFDictionary<CFString, CFType>,
    key: &str,
) -> Option<Vec<objc2_core_foundation::CFRetained<CFDictionary>>> {
    let v = value(dict, key)?;
    let arr = v.downcast_ref::<CFArray>()?;
    Some(
        as_type_array(arr)
            .iter()
            .filter_map(|item| item.downcast::<CFDictionary>().ok())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2_core_foundation::CFRetained;

    fn sample() -> CFRetained<CFDictionary<CFString, CFType>> {
        let t: &CFType = CFBoolean::new(true);
        let n = CFNumber::new_i64(501);
        let s = CFString::from_str("isaiah");
        let zero = CFNumber::new_i32(0);
        CFDictionary::from_slices(
            &[
                &*CFString::from_str("flag"),
                &*CFString::from_str("uid"),
                &*CFString::from_str("name"),
                &*CFString::from_str("numflag"),
            ],
            &[t, &n, &s, &zero],
        )
    }

    #[test]
    fn typed_reads() {
        let d = sample();
        assert_eq!(get_bool(&d, "flag"), Some(true));
        assert_eq!(get_bool(&d, "numflag"), Some(false));
        assert_eq!(get_i64(&d, "uid"), Some(501));
        assert_eq!(get_string(&d, "name").as_deref(), Some("isaiah"));
    }

    #[test]
    fn wrong_types_and_missing_keys_are_none() {
        let d = sample();
        assert_eq!(get_i64(&d, "name"), None);
        assert_eq!(get_string(&d, "uid"), None);
        assert_eq!(get_bool(&d, "name"), None);
        assert_eq!(get_bool(&d, "missing"), None);
        assert!(get_dict_array(&d, "uid").is_none());
    }

    #[test]
    fn dict_array_skips_non_dicts() {
        let inner = sample();
        let not_dict = CFString::from_str("x");
        let items: [&CFType; 2] = [&inner, &not_dict];
        let arr = CFArray::<CFType>::from_objects(&items);
        let arr_t: &CFType = &arr;
        let outer = CFDictionary::<CFString, CFType>::from_slices(
            &[&*CFString::from_str("list")],
            &[arr_t],
        );
        let got = get_dict_array(&outer, "list").expect("array present");
        assert_eq!(got.len(), 1);
        assert_eq!(get_i64(as_plist_dict(&got[0]), "uid"), Some(501));
    }
}
