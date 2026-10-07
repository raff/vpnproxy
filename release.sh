#!/bin/sh
# Create and push a version tag, which triggers the GitHub release workflow
# (.github/workflows/release.yml, on tags matching v*).
#
# usage: ./release.sh [vX.Y.Z | major | minor | patch]   (default: patch)
set -eu

cd "$(dirname "$0")"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || { echo "release.sh: must be on main (on $branch)" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "release.sh: working tree not clean" >&2; exit 1; }

git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
	{ echo "release.sh: HEAD differs from origin/main; push or pull first" >&2; exit 1; }

last=$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1)
last=${last:-v0.0.0}

bump=${1:-patch}

case $bump in
v[0-9]*) new=$bump ;;
major|minor|patch)
	IFS=. read -r maj min pat <<EOV
${last#v}
EOV
	case $bump in
	major) maj=$((maj + 1)); min=0; pat=0 ;;
	minor) min=$((min + 1)); pat=0 ;;
	patch) pat=$((pat + 1)) ;;
	esac
	new=v$maj.$min.$pat ;;
*) echo "usage: $0 [vX.Y.Z | major | minor | patch]" >&2; exit 1 ;;
esac

git rev-parse -q --verify "refs/tags/$new" >/dev/null && { echo "release.sh: tag $new already exists" >&2; exit 1; }

echo "last tag: $last"
echo "new tag:  $new  ($(git log -1 --format='%h %s'))"
printf 'Create and push %s? [y/N] ' "$new"
read -r answer
[ "$answer" = y ] || { echo "aborted"; exit 1; }

git tag -a "$new" -m "$new"
git push origin "$new"
echo "pushed $new; release workflow: https://github.com/raff/vpnproxy/actions"
