# Homebrew formula for mtuspy. This repository is its own tap.
#
# The release build rewrites the version line, the four sha256 lines by their
# marker comments and the bottle block between the BOTTLE markers. Keep the
# markers, and keep each url line directly above its sha256 line.
class Mtuspy < Formula
  desc "Path MTU discovery tool using native ICMP with Don't Fragment bit"
  homepage "https://github.com/oetiker/mtuspy"
  version "0.2.1"
  license "MIT"

  # BOTTLE-START
  bottle do
    root_url "https://github.com/oetiker/mtuspy/releases/download/v0.2.1"
    sha256 cellar: :any_skip_relocation, arm64_sonoma: "acdfb56660ab8568144c79796a38717aa49e3aed776958b2a4e8ea03117ab550"
  end
  # BOTTLE-END

  on_macos do
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "efea17bfd6648c0968d40620b2fb78bc319ce46c165613339c11ef5dd03fe11e" # mac-arm
    end
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "2b4bed9034a5325fdf7518204b7b559b935affa74ccc81542472b06ea7914e37" # mac-x86
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "97f211aea2f112737dccd99acfba57f89341a4ee73d41359f71779cfc0e412c2" # linux-x86
    end
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "cca08f173e4015f2f6cd6fe702f1f5514e0e04eb1d41c18fefd1b575f8627443" # linux-arm
    end
  end

  def install
    bin.install "mtuspy"
    Dir["man/*.[1-9]"].each { |page| (man/"man#{page[-1]}").install page }
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mtuspy --version")
  end
end
