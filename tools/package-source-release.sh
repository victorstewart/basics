#!/usr/bin/env bash
set -euo pipefail

# Produce the immutable source archive and detached DepoFiles consumed by
# downstream Depos builds. Publication is deliberately outside this script.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${1:-${repo_root}/.run/source-release}"
declared_version="$(sed -n 's/^set(BASICS_RELEASE_IDENTITY "\([^"]*\)")$/\1/p' "${repo_root}/CMakeLists.txt")"
version="${BASICS_SOURCE_RELEASE_VERSION:-${declared_version}}"

for command in cmake git gzip sha256sum tar; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "package-source-release: missing required command '${command}'." >&2
    exit 1
  }
done
[[ "${version}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "package-source-release: BASICS_SOURCE_RELEASE_VERSION is invalid." >&2
  exit 1
}
[[ -n "${declared_version}" && "${version}" == "${declared_version}" ]] || {
  echo "package-source-release: version '${version}' disagrees with source identity '${declared_version}'." >&2
  exit 1
}

git -C "${repo_root}" diff --quiet --exit-code --
git -C "${repo_root}" diff --cached --quiet --exit-code --
if [[ -n "$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "package-source-release: source worktree must be clean and fully committed." >&2
  exit 1
fi

mkdir -p "$(dirname "${output_root}")"
output_root="$(cd "$(dirname "${output_root}")" && pwd)/$(basename "${output_root}")"
asset_name="basics-${version}.tar.gz"
archive="${output_root}/${asset_name}"
depofile="${output_root}/basics.DepoFile"
local_depofile="${output_root}/basics.local.DepoFile"
receipt="${output_root}/RELEASE-RECEIPT.txt"
if [[ -e "${output_root}" ]]; then
  echo "package-source-release: candidate output already exists; choose a new output root." >&2
  exit 1
fi
mkdir -p "${output_root}"

commit="$(git -C "${repo_root}" rev-parse --verify HEAD)"
prefix="basics-${version}/"
git -C "${repo_root}" archive --format=tar --prefix="${prefix}" "${commit}" |
  gzip -n > "${archive}"

members="${output_root}/archive-members.txt"
tar -tzf "${archive}" > "${members}"
if grep -Eq '(^|/)\.git(/|$)|(^|/)\.run(/|$)' "${members}"; then
  echo "package-source-release: archive contains repository or task-local state." >&2
  exit 1
fi
if ! grep -qx "${prefix}services/memfd.h" "${members}"; then
  echo "package-source-release: archive is missing services/memfd.h." >&2
  exit 1
fi
if ! grep -qx "${prefix}tools/package-source-release.sh" "${members}"; then
  echo "package-source-release: archive does not contain its release producer." >&2
  exit 1
fi

source_url="https://github.com/victorstewart/basics/releases/download/v${version}/${asset_name}"
cmake \
  "-DBASICS_RELEASE_VERSION=${version}" \
  "-DBASICS_RELEASE_SOURCE_ARCHIVE=${archive}" \
  "-DBASICS_RELEASE_SOURCE_URL=${source_url}" \
  "-DOUTPUT=${depofile}" \
  -P "${repo_root}/tools/generate_release_depofile.cmake"
sed "s|${source_url}|file://${archive}|" "${depofile}" > "${local_depofile}"

archive_sha256="$(sha256sum "${archive}" | awk '{print $1}')"
depofile_sha256="$(sha256sum "${depofile}" | awk '{print $1}')"
local_depofile_sha256="$(sha256sum "${local_depofile}" | awk '{print $1}')"
cat > "${receipt}" <<EOF
version=${version}
source_commit=${commit}
source_url=${source_url}
archive_sha256=${archive_sha256}
depofile_sha256=${depofile_sha256}
local_depofile_sha256=${local_depofile_sha256}
EOF
(
  cd "${output_root}"
  sha256sum "${asset_name}" "basics.DepoFile" > SHA256SUMS
)
printf 'Basics source release candidate: %s\nPublishable DepoFile: %s\nLocal verification DepoFile: %s\n' \
  "${archive}" "${depofile}" "${local_depofile}"
