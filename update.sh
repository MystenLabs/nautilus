#!/bin/sh

TARGET="Containerfile"
SOURCE="https://codeberg.org/stagex/stagex/raw/branch/main/digests"
STAGES="core user bootstrap"

TMPFILE="$(mktemp)"

DIGESTS_TMP="$(mktemp)"
for stage in $STAGES; do
    curl -fsSL "$SOURCE/$stage.txt" | while read -r digest name; do
        echo "$name $digest" >> "$DIGESTS_TMP"
    done
done

while IFS= read -r line; do
    case "$line" in
        FROM\ stagex/*)
            full_image=$(echo "$line" | awk '{print $2}')
            name=$(echo "$full_image" | cut -d/ -f2 | cut -d: -f1)
            tag=$(echo "$full_image" | cut -d: -f2 | cut -d@ -f1)
            digest=""

            digest=$(awk -v name="$name" '$1 == name { print $2 }' "$DIGESTS_TMP")

            if [ -z "$digest" ]; then
                for stage in $STAGES; do
                    staged_name="$stage-$name"
                    digest=$(awk -v name="$staged_name" '$1 == name { print $2 }' "$DIGESTS_TMP")
                    [ -n "$digest" ] && name="$staged_name" && break
                done
            fi

            if [ -n "$digest" ]; then
                echo "FROM stagex/$name:$tag@sha256:$digest AS $name" >> "$TMPFILE"
            else
                echo "$line" >> "$TMPFILE"
            fi
            ;;
        *)
            echo "$line" >> "$TMPFILE"
            ;;
    esac
done < "$TARGET"

mv "$TMPFILE" "$TARGET"

rm -f "$DIGESTS_TMP"
