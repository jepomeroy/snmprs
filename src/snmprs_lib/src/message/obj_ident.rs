use std::str::FromStr;

use crate::errors::ObjectIdentifierError;

const MIN_OBJECT_IDENTIFIER_LEN: usize = 2;
const MAX_OBJECT_IDENTIFIER_LEN: usize = 128;

// X.690 packs the first two arcs into one subidentifier (40*X + Y), so X must be 0..=2
// and Y must be 0..=39 when X is 0 or 1.
const MAX_FIRST_ARC: u32 = 2;
const MAX_SECOND_ARC: u32 = 39;

/// A validated OBJECT IDENTIFIER with 2 to 128 arcs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier {
    value: Vec<u32>,
}

impl ObjectIdentifier {
    /// Validates `oid`: it must have 2 to 128 arcs, a first arc of 0 to 2, and a
    /// second arc of 0 to 39 unless the first arc is 2.
    pub fn new(oid: Vec<u32>) -> Result<Self, ObjectIdentifierError> {
        if oid.len() > MAX_OBJECT_IDENTIFIER_LEN {
            return Err(ObjectIdentifierError::TooLong {
                len: oid.len(),
                max: MAX_OBJECT_IDENTIFIER_LEN,
            });
        };

        if oid.len() < MIN_OBJECT_IDENTIFIER_LEN {
            return Err(ObjectIdentifierError::TooShort {
                len: oid.len(),
                min: MIN_OBJECT_IDENTIFIER_LEN,
            });
        };

        if oid[0] > MAX_FIRST_ARC || (oid[0] != 2 && oid[1] > MAX_SECOND_ARC) {
            return Err(ObjectIdentifierError::InvalidPrefix {
                first: oid[0],
                second: oid[1],
            });
        }

        Ok(Self { value: oid })
    }

    /// The arcs, in order.
    pub fn value(&self) -> &[u32] {
        &self.value
    }

    /// The number of arcs.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Always false, because a valid OID has at least two arcs.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl FromStr for ObjectIdentifier {
    type Err = ObjectIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let oid_vec = s
            .split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|_| ObjectIdentifierError::Parse {
                input: s.to_string(),
            })?;

        ObjectIdentifier::new(oid_vec)
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use super::*;

    #[test]
    fn test_create_obj_ident_from_str() {
        let oid_str = "1.3.4.105.99.0.1";

        let oid = ObjectIdentifier::from_str(oid_str).unwrap();
        assert_eq!(oid.value(), [1, 3, 4, 105, 99, 0, 1]);
        assert_eq!(oid.len(), 7);
    }

    #[test]
    fn test_create_obj_ident_from_vec() {
        let oid = ObjectIdentifier::new(vec![1, 3, 4, 105, 99, 0, 1]).unwrap();
        assert_eq!(oid.value(), [1, 3, 4, 105, 99, 0, 1]);
        assert_eq!(oid.len(), 7);
    }

    #[test]
    fn test_create_obj_ident_error() {
        let oid_str_arr = vec![
            (
                "1.2.3.4.5.a.6",
                "`1.2.3.4.5.a.6` is not a valid OID: expected numbers from 0 to 4294967295 separated by dots",
            ),
            (
                "1,2,3,4,5",
                "`1,2,3,4,5` is not a valid OID: expected numbers from 0 to 4294967295 separated by dots",
            ),
            (
                "1.3.",
                "`1.3.` is not a valid OID: expected numbers from 0 to 4294967295 separated by dots",
            ),
        ];
        for (oid, expected) in oid_str_arr {
            let oid = ObjectIdentifier::from_str(oid);
            assert!(oid.is_err());
            assert_eq!(oid.unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn test_create_obj_really_bad_str() {
        let oid = ObjectIdentifier::from_str("1.3.4.105084028402984092840239840.99.0.1");
        assert!(oid.is_err());
    }

    #[test]
    fn test_length_boundaries_are_accepted() {
        assert_eq!(ObjectIdentifier::new(vec![1; 2]).unwrap().len(), 2);
        assert_eq!(ObjectIdentifier::new(vec![1; 128]).unwrap().len(), 128);
        assert_eq!(ObjectIdentifier::from_str("1.3").unwrap().len(), 2);

        let longest = vec!["1"; 128].join(".");
        assert_eq!(ObjectIdentifier::from_str(&longest).unwrap().len(), 128);
    }

    #[test]
    fn test_empty_vec_is_too_short() {
        assert_eq!(
            ObjectIdentifier::new(vec![]),
            Err(ObjectIdentifierError::TooShort { len: 0, min: 2 })
        );
    }

    #[test]
    fn test_prefix_boundaries_are_accepted() {
        for (oid, oid_vec) in [
            ("0.0.1", vec![0, 0, 1]),
            ("1.39.1", vec![1, 39, 1]),
            ("2.999.1", vec![2, 999, 1]),
        ] {
            let oid = ObjectIdentifier::from_str(oid).unwrap();
            assert_eq!(oid.value, oid_vec)
        }
    }

    #[test]
    fn test_max_arc_value() {
        let oid = ObjectIdentifier::from_str("1.3.4294967295").unwrap();
        assert_eq!(oid.value(), [1, 3, u32::MAX]);
    }

    #[test]
    fn test_malformed_strings_are_parse_errors() {
        let malformed = [
            "",
            ".",
            "1..3",
            "1.3.",
            "-1.3",
            " 1.3",
            "1.3 ",
            "1.3.4294967296", // one more than u32::MAX
        ];
        for oid in malformed {
            assert_eq!(
                ObjectIdentifier::from_str(oid),
                Err(ObjectIdentifierError::Parse {
                    input: oid.to_string()
                }),
                "{:?}",
                oid
            );
        }
    }

    // Pins current behaviour: net-snmp tools print OIDs with a leading dot, but they
    // aren't accepted here. Change this test if that decision changes.
    #[test]
    fn test_leading_dot_is_rejected() {
        assert_eq!(
            ObjectIdentifier::from_str(".1.3.6"),
            Err(ObjectIdentifierError::Parse {
                input: ".1.3.6".to_string()
            })
        );
    }

    #[test]
    fn test_invalid_prefix_values() {
        for (oid, first, second) in [("3.0", 3, 0), ("1.40", 1, 40), ("0.40.1", 0, 40)] {
            assert_eq!(
                ObjectIdentifier::from_str(oid),
                Err(ObjectIdentifierError::InvalidPrefix { first, second })
            );
        }
    }

    #[test]
    fn test_invalid_prefix() {
        for oid in ["3.1.1", "1.40.1"] {
            assert!(matches!(
                ObjectIdentifier::from_str(oid),
                Err(ObjectIdentifierError::InvalidPrefix { .. })
            ));
        }
    }

    #[test]
    fn test_asn1_encoding_too_long_using_nums() {
        let oid = ObjectIdentifier::new(vec![1; 129]);
        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID length 129 is above the maximum of 128 arcs"
        );
    }

    #[test]
    fn test_asn1_encoding_too_long_using_chars() {
        let long_oid = vec!["1"; 129].join(".");
        let oid = ObjectIdentifier::from_str(&long_oid);
        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID length 129 is above the maximum of 128 arcs"
        );
    }

    #[test]
    fn test_asn1_encoding_too_short_using_nums() {
        let oid = ObjectIdentifier::new(vec![1]);

        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID length 1 is below the minimum of 2 arcs"
        );
    }

    #[test]
    fn test_asn1_encoding_too_short_using_chars() {
        let oid = ObjectIdentifier::from_str("1");
        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID length 1 is below the minimum of 2 arcs"
        );
    }
}
