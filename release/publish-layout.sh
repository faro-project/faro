#!/bin/bash
# The one place that knows where the update layout is published.
#
#   release/publish-layout.sh pull DIR          # the published timestamp.json and
#                                               # targets.json into DIR (none at first)
#   release/publish-layout.sh push DIR MESSAGE  # add DIR's files to the publishing location
#
# The layout is served as plain files at FARO_UPDATES_URL
# (https://updates.faro-project.org/), which instances use as
# `updates.upstream`. Today that is GitHub Pages on the public repository
# FARO_UPDATES_REPO (faro-project/updates), branch FARO_UPDATES_BRANCH
# (main). To move the layout elsewhere (object storage behind a CDN, say),
# change this script only: the workflows call `pull` and `push` and nothing
# else. docs/DEVELOPMENT.md "Releasing" compares the options.
#
# `push` only adds or replaces files, never deletes one: older releases
# stay listed in targets.json, so their artifacts must stay served. An
# artifact under targets/ is never replaced with different bytes; the
# metadata files (timestamp.json, targets.json, roots/) are. It works on
# the repository without checking it out, so artifacts already published
# are never downloaded.
#
# Environment:
#   FARO_UPDATES_REPO         owner/name (default faro-project/updates)
#   FARO_UPDATES_BRANCH       the branch Pages serves (default main)
#   FARO_UPDATES_URL          the public URL, for the CNAME file
#                             (default https://updates.faro-project.org/)
#   FARO_UPDATES_DEPLOY_KEY   an SSH private key with write access to the
#                             repository (a deploy key); needed for push
#   FARO_UPDATES_GIT_URL      overrides the repository URL (tests use a
#                             local bare repository)
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

repo_name="${FARO_UPDATES_REPO:-faro-project/updates}"
branch="${FARO_UPDATES_BRANCH:-main}"
url="${FARO_UPDATES_URL:-https://updates.faro-project.org/}"
host="${url#https://}"
host="${host%%/*}"
# GitHub refuses files over 100 MB and warns above 50 MB.
max_bytes=$((100 * 1000 * 1000))
warn_bytes=$((50 * 1000 * 1000))

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Never wait for a password: fail instead.
export GIT_TERMINAL_PROMPT=0

git_url() {
    if [[ -n "${FARO_UPDATES_GIT_URL:-}" ]]; then
        echo "$FARO_UPDATES_GIT_URL"
    elif [[ -n "${FARO_UPDATES_DEPLOY_KEY:-}" ]]; then
        echo "git@github.com:$repo_name.git"
    else
        echo "https://github.com/$repo_name.git"
    fi
}

# SSH with the deploy key only, and GitHub's published host key only
# (https://api.github.com/meta), so nothing on the runner is trusted.
setup_ssh() {
    [[ -n "${FARO_UPDATES_DEPLOY_KEY:-}" ]] || return 0
    (umask 077 && printf '%s\n' "$FARO_UPDATES_DEPLOY_KEY" > "$work/deploy_key")
    echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" \
        > "$work/known_hosts"
    export GIT_SSH_COMMAND="ssh -F /dev/null -i $work/deploy_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$work/known_hosts"
}

# A clone without a working tree or any file contents; blobs are fetched
# only when read. Sets HAVE_HEAD when the branch exists.
open_repo() {
    setup_ssh
    local u
    u="$(git_url)"
    git init -q --bare "$work/repo.git"
    export GIT_DIR="$work/repo.git"
    git remote add origin "$u"
    HAVE_HEAD=0
    if [[ -n "$(git ls-remote --heads origin "refs/heads/$branch")" ]]; then
        git -c protocol.version=2 fetch -q --depth 1 --filter=blob:none origin \
            "+refs/heads/$branch:refs/remotes/origin/$branch"
        HAVE_HEAD=1
    fi
}

pull() {
    local dir="$1" f
    mkdir -p "$dir"
    open_repo
    if (( ! HAVE_HEAD )); then
        echo "nothing published yet at $(git_url) ($branch)"
        return 0
    fi
    for f in timestamp.json targets.json; do
        if git cat-file -e "origin/$branch:$f" 2>/dev/null; then
            git cat-file blob "origin/$branch:$f" > "$dir/$f"
            echo "pulled $f"
        fi
    done
}

file_size() {
    wc -c < "$1" | tr -d ' '
}

push() {
    local dir="$1" message="$2" rel new old size tree parent commit
    [[ -f "$dir/timestamp.json" ]] || die "$dir has no timestamp.json"
    [[ -n "${FARO_UPDATES_DEPLOY_KEY:-}${FARO_UPDATES_GIT_URL:-}" ]] ||
        die "push needs FARO_UPDATES_DEPLOY_KEY, a deploy key with write access to $repo_name"
    open_repo
    export GIT_INDEX_FILE="$work/index"
    if (( HAVE_HEAD )); then
        git read-tree "origin/$branch"
    else
        git read-tree --empty
    fi
    add_blob() { # path-in-repo, content-file
        git update-index --add --cacheinfo "100644,$(git hash-object -w "$2"),$1"
    }
    # Pages serves files as they are (no Jekyll) on the custom domain.
    printf '%s\n' "$host" > "$work/CNAME"
    : > "$work/.nojekyll"
    add_blob CNAME "$work/CNAME"
    add_blob .nojekyll "$work/.nojekyll"
    # Artifacts first and the timestamp last, in one commit: a mirror never
    # sees a timestamp for files that aren't there.
    while IFS= read -r rel; do
        size="$(file_size "$dir/$rel")"
        (( size <= max_bytes )) || die "$rel is $size bytes: GitHub Pages takes files up to 100 MB"
        (( size <= warn_bytes )) ||
            echo "::warning title=Large artifact::$rel is $size bytes; GitHub refuses files over 100 MB."
        new="$(git hash-object -w "$dir/$rel")"
        old="$(git rev-parse -q --verify "origin/$branch:$rel" 2>/dev/null || true)"
        if [[ "$rel" == targets/* && -n "$old" && "$old" != "$new" ]]; then
            die "$rel is already published with different content; an artifact is never replaced"
        fi
        git update-index --add --cacheinfo "100644,$new,$rel"
    done < <(cd "$dir" && find . -type f ! -name timestamp.json | sed 's|^\./||' | LC_ALL=C sort)
    add_blob timestamp.json "$dir/timestamp.json"

    tree="$(git write-tree)"
    parent=()
    if (( HAVE_HEAD )); then
        if [[ "$tree" == "$(git rev-parse "origin/$branch^{tree}")" ]]; then
            echo "nothing to publish: the layout is already there"
            return 0
        fi
        parent=(-p "origin/$branch")
    fi
    commit="$(GIT_AUTHOR_NAME="Faro release" GIT_AUTHOR_EMAIL="release@faro-project.org" \
        GIT_COMMITTER_NAME="Faro release" GIT_COMMITTER_EMAIL="release@faro-project.org" \
        git commit-tree "$tree" "${parent[@]+"${parent[@]}"}" -m "$message")"
    # No force: if someone else published in between, this fails and the
    # run can be retried on top of it.
    git push -q origin "$commit:refs/heads/$branch"
    echo "published $commit to $(git_url) ($branch); served at $url"
}

case "${1:-}" in
    pull) [[ $# -eq 2 ]] || die "usage: $0 pull DIR"; pull "$2" ;;
    push) [[ $# -eq 3 ]] || die "usage: $0 push DIR MESSAGE"; push "$2" "$3" ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
