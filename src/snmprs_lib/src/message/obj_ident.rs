use std::str::FromStr;

use asn1_rs::Oid;

use crate::errors::ObjectIdentifierError;

const MIN_OBJECT_IDENTIFIER_LEN: usize = 2;
const MAX_OBJECT_IDENTIFIER_LEN: usize = 128;

// The first two arcs share one byte on the wire, and asn1-rs only encodes these ranges.
const MAX_FIRST_ARC: u32 = 2;
const MAX_SECOND_ARC: u32 = 39;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier {
    value: Vec<u32>,
}

impl ObjectIdentifier {
    pub fn new(oid: Vec<u32>) -> Result<Self, ObjectIdentifierError> {
        if oid.len() > MAX_OBJECT_IDENTIFIER_LEN {
            return Err(ObjectIdentifierError::TooLong(
                oid.len(),
                MAX_OBJECT_IDENTIFIER_LEN,
            ));
        };

        if oid.len() < MIN_OBJECT_IDENTIFIER_LEN {
            return Err(ObjectIdentifierError::TooShort(
                oid.len(),
                MIN_OBJECT_IDENTIFIER_LEN,
            ));
        };

        if oid[0] > MAX_FIRST_ARC || oid[1] > MAX_SECOND_ARC {
            return Err(ObjectIdentifierError::InvalidPrefix(oid[0], oid[1]));
        }

        Ok(Self { value: oid })
    }

    pub fn value(&self) -> &[u32] {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub(super) fn to_oid(&self) -> Result<Oid<'static>, ObjectIdentifierError> {
        let arcs: Vec<u64> = self.value.iter().map(|&arc| u64::from(arc)).collect();
        Oid::from(&arcs)
            .map_err(|_| ObjectIdentifierError::InvalidPrefix(self.value[0], self.value[1]))
    }
}

impl FromStr for ObjectIdentifier {
    type Err = ObjectIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let oid_vec = s
            .split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|_| ObjectIdentifierError::ParseError(s.to_string()))?;

        ObjectIdentifier::new(oid_vec)
    }
}

#[cfg(test)]
mod test {
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
                "Parse error: 1.2.3.4.5.a.6 is not the right format",
            ),
            (
                "1,2,3,4,5",
                "Parse error: 1,2,3,4,5 is not the right format",
            ),
            ("1.3.", "Parse error: 1.3. is not the right format"),
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
    fn test_asn1_encoding() {
        let oid = ObjectIdentifier::from_str("1.3.5.7.11.13.17").unwrap();
        assert_eq!(oid.to_oid().unwrap().to_id_string(), "1.3.5.7.11.13.17");
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
            Err(ObjectIdentifierError::TooShort(0, 2))
        );
    }

    #[test]
    fn test_prefix_boundaries_are_accepted() {
        for (oid, encoded_prefix) in [("0.0.1", 0x00), ("1.39.1", 0x4f), ("2.39.1", 0x77)] {
            let oid = ObjectIdentifier::from_str(oid).unwrap();
            assert_eq!(oid.to_oid().unwrap().as_bytes(), [encoded_prefix, 0x01]);
        }
    }

    #[test]
    fn test_max_arc_value() {
        let oid = ObjectIdentifier::from_str("1.3.4294967295").unwrap();
        assert_eq!(oid.value(), [1, 3, u32::MAX]);
        assert_eq!(
            oid.to_oid().unwrap().as_bytes(),
            [0x2b, 0x8f, 0xff, 0xff, 0xff, 0x7f]
        );
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
                Err(ObjectIdentifierError::ParseError(oid.to_string())),
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
            Err(ObjectIdentifierError::ParseError(".1.3.6".to_string()))
        );
    }

    #[test]
    fn test_invalid_prefix_values() {
        for (oid, first, second) in [("3.0", 3, 0), ("2.40", 2, 40), ("0.40.1", 0, 40)] {
            assert_eq!(
                ObjectIdentifier::from_str(oid),
                Err(ObjectIdentifierError::InvalidPrefix(first, second))
            );
        }
    }

    #[test]
    fn test_invalid_prefix() {
        for oid in ["3.1.1", "1.40.1"] {
            assert!(matches!(
                ObjectIdentifier::from_str(oid),
                Err(ObjectIdentifierError::InvalidPrefix(_, _))
            ));
        }
    }

    #[test]
    fn test_asn1_encoding_too_long_using_nums() {
        let oid = ObjectIdentifier::new(vec![1; 129]);
        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID of length 129 exceeds the maximum: 128"
        );
    }

    #[test]
    fn test_asn1_encoding_too_long_using_chars() {
        let long_oid = vec!["1"; 129].join(".");
        let oid = ObjectIdentifier::from_str(&long_oid);
        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID of length 129 exceeds the maximum: 128"
        );
    }

    #[test]
    fn test_asn1_encoding_too_short_using_nums() {
        let oid = ObjectIdentifier::new(vec![1]);

        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID of length 1 is too short: minimum is 2"
        );
    }

    #[test]
    fn test_asn1_encoding_too_short_using_chars() {
        let oid = ObjectIdentifier::from_str("1");
        assert!(oid.is_err());
        assert_eq!(
            oid.unwrap_err().to_string(),
            "OID of length 1 is too short: minimum is 2"
        );
    }
}
