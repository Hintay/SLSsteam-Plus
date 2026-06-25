#include "config.hpp"

#include "config_default.hpp"
#include "feats/package.hpp"
#include "filewatcher.hpp"
#include "log.hpp"
#include "lua/LuaLoader.hpp"
#include "lua/ManifestProvider.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <regex>
#include <string>
#include <unordered_set>
#include <vector>


std::string CConfig::getDir()
{
	char pathBuf[255];
	const char* configDir = getenv("XDG_CONFIG_HOME"); //Most users should have this set iirc
	if (configDir != NULL)
	{
		sprintf(pathBuf, "%s/SLSsteam", configDir);
	}
	else
	{
		const char* home = getenv("HOME");
		sprintf(pathBuf, "%s/.config/SLSsteam", home);
	}

	return std::string(pathBuf);
}

std::string CConfig::getPath()
{
	return getDir().append("/config.toml");
}

bool CConfig::createFile()
{
	std::string path = getPath();
	if (!std::filesystem::exists(path))
	{
		std::string dir = getDir();
		if (!std::filesystem::exists(dir))
		{
			if (!std::filesystem::create_directory(dir))
			{
				g_pLog->notify("Unable to create config directory at %s!\n", dir.c_str());
				return false;
			}

			g_pLog->debug("Created config directory at %s\n", dir.c_str());
		}

		FILE* file = fopen(path.c_str(), "w");
		if (!file)
		{
			g_pLog->notify("Unable to create config at %s!\n", path.c_str());
			return false;
		}

		fputs(defaultConfig, file);
		fflush(file);
		fclose(file);
	}

	return true;
}

// ============================================================================
// TOML config entries that may be absent in configs created before they were
// introduced. Each entry carries a category label that maps to the section
// headers in config_default.hpp (e.g. "# --- Core ---"). When a key is
// missing, the entry is inserted at the end of its category section rather
// than dumped at the bottom of the file.
// ============================================================================

struct NewConfigEntry {
	const char* key;
	const char* category;
	const char* block;
};

static const NewConfigEntry kNewConfigEntries[] = {
	// --- Core ---
	{ "DisableCloud", "Core",
	  "# Disable cloud saves for unlocked games. Set to false if using CloudRedirect or similar.\n"
	  "DisableCloud = true\n" },

	// --- Advanced ---
	{ "ProtonInject", "Advanced",
	  "# Inject a pre-compiled Windows DLL into Proton game processes.\n"
	  "# Path: absolute Linux path to the DLL.\n"
	  "# Apps: list of AppIds to inject into (optional if Flag is set).\n"
	  "# Flag: a Steam launch option that triggers injection for any game.\n"
	  "#   The flag is stripped from argv before the game sees it.\n"
	  "# Requires sls_proton_inject.so (next to SLSsteam.so, or under /usr/lib).\n"
	  "# Example:\n"
	  "#   [ProtonInject]\n"
	  "#   [[ProtonInject.Dlls]]\n"
	  "#   Path = \"/home/deck/.config/SLSsteam/OnlineFix.dll\"\n"
	  "#   Flag = \"-onlinefix\"\n" },

	// --- Internal ---
	{ "OnlinePatterns", "Internal",
	  "# Fetch the latest patterns online (HTTPS) on startup to pick up updated\n"
	  "# signatures and IPC method hashes for new Steam builds without re-downloading SLSsteam.\n"
	  "#OnlinePatterns = true\n" },

	{ "OfflineAchievementsSchema", "Internal",
	  "# Use only pre-generated offline schema files (e.g. from SLScheevo) instead\n"
	  "# of redirecting stats requests to a donor SteamID. When enabled, achievement\n"
	  "# data comes exclusively from local bin files in appcache/stats/.\n"
	  "#OfflineAchievementsSchema = false\n" },

	{ "PackageInjection", "Internal",
	  "# Inject added apps into Steam's live package table (pkg0) and re-evaluate\n"
	  "# licenses without a restart.\n"
	  "#PackageInjection = true\n" },

	{ "BlockTicketRequests", "Internal",
	  "# Drop outbound ownership-ticket network requests and suppress remote\n"
	  "# BUpdateAppOwnershipTicket for spoofed apps. Cached tickets are always\n"
	  "# injected regardless of this setting.\n"
	  "#BlockTicketRequests = true\n" },

	{ "Manifest", "Internal",
	  "# Manifest settings for download functionality.\n"
	  "# Built-in request-code providers: opensteamtool / wudrm / steamrun.\n"
	  "# Providers is the ordered fallback chain.\n"
	  "#[Manifest]\n"
	  "#Providers = [\"opensteamtool\", \"wudrm\", \"steamrun\"]\n"
	  "#UseLuaManifestOverrides = true\n"
	  "#TimeoutConnectMs = 5000\n"
	  "#TimeoutTotalMs = 10000\n"
	  "#ReuseConnection = true\n" },

	{ "Lua", "Internal",
	  "# Additional Lua plugin directories scanned after the built-in Steam and user config dirs.\n"
	  "#[Lua]\n"
	  "#Paths = []\n" },
};

// Check whether a top-level key or section header (active or commented-out)
// already exists in a TOML config file. Matches lines like:
//   Key = ...   |   #Key = ...   |   # Key = ...
//   [Key]       |   #[Key]       |   # [Key]
//   [Key.       |   #[Key.       |   # [Key.
static bool configHasKey(const std::string& content, const char* key)
{
	// Bare-key forms (Key = ...)
	const std::string active   = std::string(key) + " ";
	const std::string activeEq = std::string(key) + "=";
	const std::string hash     = std::string("#") + key;
	const std::string hashSp   = std::string("# ") + key;
	// Section header forms ([Key] or [Key.)
	const std::string section  = std::string("[") + key;
	const std::string hashSec  = std::string("#[") + key;
	const std::string hashSpSec = std::string("# [") + key;

	size_t pos = 0;
	while (pos < content.size())
	{
		const size_t lineEnd = content.find('\n', pos);
		const size_t len = (lineEnd == std::string::npos ? content.size() : lineEnd) - pos;
		const std::string_view line(content.data() + pos, len);
		std::string_view normalized = line;
		while (!normalized.empty() && (normalized.front() == ' ' || normalized.front() == '\t'))
			normalized.remove_prefix(1);
		if (!normalized.empty() && normalized.front() == '#')
		{
			normalized.remove_prefix(1);
			while (!normalized.empty() && (normalized.front() == ' ' || normalized.front() == '\t'))
				normalized.remove_prefix(1);
		}

		if (line.starts_with(active) || line.starts_with(activeEq) ||
		    line.starts_with(hash)   || line.starts_with(hashSp)   ||
		    line.starts_with(section) || line.starts_with(hashSec) || line.starts_with(hashSpSec) ||
		    normalized.starts_with(active) || normalized.starts_with(activeEq) ||
		    normalized.starts_with(section))
			return true;

		pos = (lineEnd == std::string::npos) ? content.size() : lineEnd + 1;
	}
	return false;
}

// Full header lines for each category label. Used when creating a category
// section that doesn't exist yet (e.g. YAML-converted configs).
static const struct { const char* label; const char* header; } kCategoryHeaders[] = {
	{ "Core",     "# --- Core ---" },
	{ "Optional", "# --- Optional (uncomment to customize) ---" },
	{ "Advanced", "# --- Advanced ---" },
	{ "Internal", "# --- Internal (default values are optimal for most users) ---" },
};

// Find the insertion point for new entries in a category section.
// Searches for "# --- {category}" prefix and returns the position just before
// the next category header (or EOF). Returns npos if the category is absent.
static size_t findCategoryInsertPos(const std::string& content, const char* category)
{
	const std::string prefix = std::string("# --- ") + category;
	const size_t headerPos = content.find(prefix);
	if (headerPos == std::string::npos)
		return std::string::npos;

	const size_t afterHeader = content.find('\n', headerPos);
	if (afterHeader == std::string::npos)
		return content.size();

	const size_t nextHeader = content.find("\n# --- ", afterHeader);
	return (nextHeader != std::string::npos) ? nextHeader : content.size();
}

// ============================================================================
// Built-in YAML → TOML config converter.
//
// Two-pass design: bare keys first, [Section] tables last — avoids TOML's
// section-capture behavior where [Foo] absorbs all subsequent key-value pairs.
//
// Ported from tools/yaml_to_toml_config.py (validated against 558-line prod config).
// ============================================================================

namespace {

static bool isIntegerStr(const std::string& v)
{
	if (v.empty()) return false;
	size_t start = (v[0] == '-') ? 1 : 0;
	if (start >= v.size()) return false;
	for (size_t j = start; j < v.size(); ++j)
		if (!std::isdigit(static_cast<unsigned char>(v[j]))) return false;
	return true;
}

static std::string convValue(const std::string& v)
{
	{
		std::string lower = v;
		for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		if (lower == "yes" || lower == "true" || lower == "on") return "true";
		if (lower == "no"  || lower == "false" || lower == "off") return "false";
	}
	if (v == "[]") return "[]";
	if (isIntegerStr(v)) return v;
	if (v.size() >= 2 && v.front() == '"' && v.back() == '"') return v;
	return "\"" + v + "\"";
}

// Split "value # comment" into (value, comment). Only splits when the
// pre-comment part is an integer or quoted string.
static std::pair<std::string, std::string> stripInlineComment(const std::string& s)
{
	// Find " # " or "  #" pattern (whitespace then hash)
	for (size_t p = 1; p < s.size(); ++p)
	{
		if (s[p] == '#' && s[p - 1] == ' ')
		{
			std::string val = s.substr(0, p);
			while (!val.empty() && val.back() == ' ') val.pop_back();
			std::string comment = (p + 1 < s.size() && s[p + 1] == ' ')
				? s.substr(p + 2) : s.substr(p + 1);
			if (isIntegerStr(val) || (val.size() >= 2 && val.front() == '"' && val.back() == '"'))
				return {val, comment};
			break;
		}
	}
	return {s, ""};
}

static std::string quoteArr(const std::vector<std::pair<std::string, std::string>>& items,
                            bool hasComments)
{
	bool allNums = true;
	for (const auto& [d, _] : items)
	{
		if (!isIntegerStr(d)) { allNums = false; break; }
	}

	if (items.size() <= 5 && !hasComments)
	{
		std::string result = "[";
		for (size_t idx = 0; idx < items.size(); ++idx)
		{
			if (idx > 0) result += ", ";
			if (allNums) result += items[idx].first;
			else result += "\"" + items[idx].first + "\"";
		}
		result += "]";
		return result;
	}

	// Multiline
	std::string result = "[\n";
	for (const auto& [d, cm] : items)
	{
		std::string valStr = allNums ? d : "\"" + d + "\"";
		if (!cm.empty())
			result += "  " + valStr + ", # " + cm + "\n";
		else
			result += "  " + valStr + ",\n";
	}
	result += "]";
	return result;
}

// Indentation level of a line (number of leading spaces).
static size_t indentOf(const std::string& line)
{
	size_t n = 0;
	while (n < line.size() && line[n] == ' ') ++n;
	return n;
}

// Trim leading whitespace.
static std::string lstrip(const std::string& s)
{
	size_t n = 0;
	while (n < s.size() && (s[n] == ' ' || s[n] == '\t')) ++n;
	return s.substr(n);
}

// Item types collected from YAML child lines.
struct YamlItem {
	enum Type { LIST_ITEM, KV, SUB_SECTION };
	Type type;
	std::string key;     // For KV/SUB_SECTION: the sub-key name
	std::string val;     // For KV/LIST_ITEM: the scalar value
	std::string comment; // Inline comment if any
	std::vector<YamlItem> children; // For SUB_SECTION: nested items
};

// The main YAML→TOML converter.  See Python prototype for specification.
static std::string convertYamlToToml(const std::string& yamlText)
{
	std::vector<std::string> lines;
	{
		std::istringstream iss(yamlText);
		std::string tmp;
		while (std::getline(iss, tmp))
			lines.push_back(tmp);
	}

	// bare_keys: vector of (comment_lines, toml_line)
	std::vector<std::pair<std::vector<std::string>, std::string>> bareKeys;
	// sections: vector of (comment_lines, section_name, content_lines)
	struct Section {
		std::vector<std::string> comments;
		std::string name;
		std::vector<std::string> content;
	};
	std::vector<Section> sections;
	std::vector<std::string> commentBuf;

	size_t i = 0;
	while (i < lines.size())
	{
		const std::string& raw = lines[i];
		std::string stripped = lstrip(raw);
		size_t indent = indentOf(raw);

		// Blank or comment line — buffer for attachment to next key
		if (stripped.empty() || stripped[0] == '#')
		{
			commentBuf.push_back(raw);
			++i;
			continue;
		}
		// Indented line at top level is unexpected — skip with comment
		if (indent != 0)
		{
			commentBuf.push_back("# [skipped] " + raw);
			++i;
			continue;
		}

		// Match "Key: value" or "Key:" (section opener)
		static const std::regex keyRe(R"(^([\w]+):\s*(.*))");
		std::smatch km;
		if (!std::regex_match(stripped, km, keyRe))
		{
			commentBuf.push_back(raw);
			++i;
			continue;
		}

		std::string key = km[1].str();
		std::string val = km[2].str();

		// Pattern 1: "Key: value" — scalar on same line
		if (!val.empty())
		{
			auto [valClean, inlineCmt] = stripInlineComment(val);
			std::string line = key + " = " + convValue(valClean);
			if (!inlineCmt.empty()) line += " # " + inlineCmt;
			bareKeys.push_back({commentBuf, line});
			commentBuf.clear();
			++i;
			continue;
		}

		// "Key:" with no value — collect children
		++i;
		std::vector<YamlItem> l2Items;
		std::vector<std::pair<std::string, std::string>> l2Comments; // (type="comment", text)

		while (i < lines.size())
		{
			const std::string& cr = lines[i];
			std::string cs = lstrip(cr);
			size_t ci = indentOf(cr);
			if (cs.empty()) { ++i; continue; }
			if (ci < 2 && cs[0] != '#') break;
			if (cs[0] == '#')
			{
				l2Comments.push_back({"comment", cs});
				++i;
				continue;
			}

			if (cs.size() >= 2 && cs[0] == '-' && cs[1] == ' ')
			{
				// List item
				std::string itemRaw = lstrip(cs.substr(2));
				auto [vc, ic] = stripInlineComment(itemRaw);
				YamlItem item;
				item.type = YamlItem::LIST_ITEM;
				item.val = vc;
				item.comment = ic;
				l2Items.push_back(item);
				++i;
			}
			else if (cs.find(':') != std::string::npos)
			{
				std::smatch cm2;
				if (!std::regex_match(cs, cm2, keyRe)) { ++i; continue; }
				std::string sk = cm2[1].str();
				std::string sv = cm2[2].str();

				if (!sv.empty())
				{
					// Sub-key with value
					auto [svClean, svCmt] = stripInlineComment(sv);
					YamlItem item;
					item.type = YamlItem::KV;
					item.key = sk;
					item.val = svClean;
					item.comment = svCmt;
					l2Items.push_back(item);
					++i;
				}
				else
				{
					// Sub-section: "SubKey:" with deeper children
					++i;
					std::vector<YamlItem> l4Items;
					while (i < lines.size())
					{
						const std::string& r4 = lines[i];
						std::string s4 = lstrip(r4);
						size_t i4 = indentOf(r4);
						if (s4.empty()) { ++i; continue; }
						if (s4[0] == '#' && i4 >= 3) { ++i; continue; }
						if (i4 < 4) break;

						if (s4.size() >= 2 && s4[0] == '-' && s4[1] == ' ')
						{
							std::string v4 = lstrip(s4.substr(2));
							auto [v4c, v4cm] = stripInlineComment(v4);
							YamlItem sub;
							sub.type = YamlItem::LIST_ITEM;
							sub.val = v4c;
							sub.comment = v4cm;
							l4Items.push_back(sub);
						}
						else if (s4.find(':') != std::string::npos)
						{
							std::smatch cm4;
							if (std::regex_match(s4, cm4, keyRe))
							{
								auto [v4c, v4cm] = stripInlineComment(cm4[2].str());
								YamlItem sub;
								sub.type = YamlItem::KV;
								sub.key = cm4[1].str();
								sub.val = v4c;
								sub.comment = v4cm;
								l4Items.push_back(sub);
							}
						}
						++i;
					}

					YamlItem item;
					item.type = YamlItem::SUB_SECTION;
					item.key = sk;
					item.children = std::move(l4Items);
					l2Items.push_back(item);
				}
			}
			else
			{
				++i;
			}
		}

		// Classify and emit
		if (l2Items.empty())
		{
			bareKeys.push_back({commentBuf, "# " + key + ": (empty, using default)"});
			commentBuf.clear();
			continue;
		}

		// All list items → array (bare key)
		bool allList = true;
		for (const auto& it : l2Items)
			if (it.type != YamlItem::LIST_ITEM) { allList = false; break; }

		if (allList)
		{
			std::vector<std::pair<std::string, std::string>> items;
			for (const auto& it : l2Items)
				items.push_back({it.val, it.comment});
			bool hasCmt = !l2Comments.empty();
			for (const auto& [_, cm] : items)
				if (!cm.empty()) { hasCmt = true; break; }
			std::string arrStr = quoteArr(items, hasCmt);

			if (arrStr.find('\n') != std::string::npos)
			{
				// Insert section-level comments at top of multiline array
				auto arrLines = std::vector<std::string>();
				{
					std::istringstream iss(arrStr);
					std::string tmp;
					while (std::getline(iss, tmp))
						arrLines.push_back(tmp);
				}
				std::string result = arrLines[0] + "\n";
				for (const auto& [_, cc] : l2Comments)
					result += "  " + cc + "\n";
				for (size_t idx = 1; idx < arrLines.size(); ++idx)
					result += arrLines[idx] + (idx + 1 < arrLines.size() ? "\n" : "");
				bareKeys.push_back({commentBuf, key + " = " + result});
			}
			else
			{
				bareKeys.push_back({commentBuf, key + " = " + arrStr});
			}
			commentBuf.clear();
			continue;
		}

		// Check for nested sub-sections with children
		bool hasNested = false;
		for (const auto& it : l2Items)
			if (it.type == YamlItem::SUB_SECTION && !it.children.empty())
			{ hasNested = true; break; }

		if (hasNested)
		{
			// Check if ALL sub-sections have KV children (DlcData pattern)
			bool allSubKv = true;
			bool hasSubLists = false;
			for (const auto& it : l2Items)
			{
				if (it.type != YamlItem::SUB_SECTION || it.children.empty()) continue;
				for (const auto& c : it.children)
				{
					if (c.type == YamlItem::LIST_ITEM) hasSubLists = true;
					if (c.type != YamlItem::KV) allSubKv = false;
				}
			}

			if (allSubKv && !hasSubLists)
			{
				// DlcData pattern: [Key.SubKey] tables
				for (const auto& it : l2Items)
				{
					if (it.type != YamlItem::SUB_SECTION || it.children.empty()) continue;
					std::vector<std::string> sub;
					for (const auto& c : it.children)
					{
						std::string line = c.key + " = " + convValue(c.val);
						if (!c.comment.empty()) line += " # " + c.comment;
						sub.push_back(line);
					}
					sections.push_back({commentBuf, key + "." + it.key, sub});
					commentBuf.clear();
				}
			}
			else
			{
				// Mixed or DenuvoGames pattern: [Key] with flat entries
				std::vector<std::string> content;
				for (const auto& it : l2Items)
				{
					if (it.type == YamlItem::KV)
					{
						std::string line = it.key + " = " + convValue(it.val);
						if (!it.comment.empty()) line += " # " + it.comment;
						content.push_back(line);
					}
					else if (it.type == YamlItem::SUB_SECTION && !it.children.empty())
					{
						// Check if all children are list items
						bool childAllList = true;
						for (const auto& c : it.children)
							if (c.type != YamlItem::LIST_ITEM) { childAllList = false; break; }

						if (childAllList)
						{
							std::vector<std::pair<std::string, std::string>> items;
							for (const auto& c : it.children)
								items.push_back({c.val, c.comment});
							content.push_back(it.key + " = " + quoteArr(items, false));
						}
						else
						{
							for (const auto& c : it.children)
							{
								std::string line = c.key + " = " + convValue(c.val);
								if (!c.comment.empty()) line += " # " + c.comment;
								content.push_back(line);
							}
						}
					}
				}
				sections.push_back({commentBuf, key, content});
				commentBuf.clear();
			}
		}
		else
		{
			// Simple table: [Key] with flat sub-keys or sub-lists
			std::vector<std::string> content;
			for (const auto& it : l2Items)
			{
				if (it.type == YamlItem::KV)
				{
					std::string line = it.key + " = " + convValue(it.val);
					if (!it.comment.empty()) line += " # " + it.comment;
					content.push_back(line);
				}
				else if (it.type == YamlItem::SUB_SECTION && !it.children.empty())
				{
					std::vector<std::pair<std::string, std::string>> items;
					for (const auto& c : it.children)
						items.push_back({c.val, c.comment});
					content.push_back(it.key + " = " + quoteArr(items, false));
				}
				else if (it.type == YamlItem::SUB_SECTION && it.children.empty())
				{
					content.push_back(it.key + " = []");
				}
			}
			sections.push_back({commentBuf, key, content});
			commentBuf.clear();
		}
	}

	// Two-pass output: bare keys first, then sections
	std::string out;
	for (const auto& [comments, line] : bareKeys)
	{
		for (const auto& c : comments) out += c + "\n";
		out += line + "\n";
	}
	for (const auto& sec : sections)
	{
		out += "\n";
		for (const auto& c : sec.comments) out += c + "\n";
		out += "[" + sec.name + "]\n";
		for (const auto& l : sec.content) out += l + "\n";
	}
	// Trailing comment buffer
	for (const auto& c : commentBuf) out += c + "\n";

	// Remove trailing newline to match Python output (join vs concat)
	if (!out.empty() && out.back() == '\n') out.pop_back();

	// Collapse triple+ blank lines (converter artifacts from comment buffering)
	{
		size_t pos;
		while ((pos = out.find("\n\n\n")) != std::string::npos)
			out.erase(pos, 1);
	}

	return out;
}

} // anonymous namespace

void CConfig::migrateConfig()
{
	const std::string tomlPath = getPath();
	const std::string yamlPath = getDir() + "/config.yaml";

	// Phase 1: YAML → TOML conversion (only if config.yaml exists and config.toml does not)
	if (!std::filesystem::exists(tomlPath) && std::filesystem::exists(yamlPath))
	{
		std::string yamlContent;
		{
			std::ifstream in(yamlPath, std::ios::binary);
			if (!in)
			{
				g_pLog->notify("Config: cannot read %s for migration\n", yamlPath.c_str());
				return;
			}
			yamlContent.assign(std::istreambuf_iterator<char>(in),
			                   std::istreambuf_iterator<char>());
		}

		std::string tomlContent = convertYamlToToml(yamlContent);

		{
			std::ofstream out(tomlPath, std::ios::binary);
			if (!out)
			{
				g_pLog->notify("Config: cannot write %s\n", tomlPath.c_str());
				return;
			}
			out << tomlContent;
			out.flush();
		}

		// Rename old config to .bak
		std::error_code ec;
		std::filesystem::rename(yamlPath, yamlPath + ".bak", ec);
		if (ec)
			g_pLog->info("Config: could not rename %s to .bak: %s\n",
			             yamlPath.c_str(), ec.message().c_str());

		g_pLog->info("Config: migrated YAML → TOML (%s)\n", tomlPath.c_str());
	}

	// Phase 2: Insert missing TOML entries into their category sections
	if (!std::filesystem::exists(tomlPath))
		return;

	std::string content;
	{
		std::ifstream in(tomlPath, std::ios::binary);
		if (!in) return;
		content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	}

	// Group missing entries by category, preserving definition order
	struct CatGroup { std::string category; std::string entries; };
	std::vector<CatGroup> groups;

	for (const auto& entry : kNewConfigEntries)
	{
		if (configHasKey(content, entry.key))
			continue;

		CatGroup* grp = nullptr;
		for (auto& g : groups)
			if (g.category == entry.category) { grp = &g; break; }
		if (!grp)
		{
			groups.push_back({entry.category, ""});
			grp = &groups.back();
		}
		grp->entries += '\n';
		grp->entries += entry.block;
	}

	if (groups.empty())
		return;

	// Collect insertions: entries whose category header exists in the file
	// are inserted at the end of that section; others are appended at EOF
	// with a new category header.
	struct Insertion { size_t pos; std::string text; };
	std::vector<Insertion> insertions;
	std::string appendix;

	for (const auto& grp : groups)
	{
		const size_t pos = findCategoryInsertPos(content, grp.category.c_str());
		if (pos != std::string::npos)
		{
			insertions.push_back({pos, grp.entries});
		}
		else
		{
			// Look up full header text for this category label
			const char* header = nullptr;
			for (const auto& cat : kCategoryHeaders)
				if (grp.category == cat.label) { header = cat.header; break; }

			appendix += "\n\n";
			appendix += header ? header : (std::string("# --- ") + grp.category + " ---").c_str();
			appendix += grp.entries;
		}
	}

	// Process insertions in reverse file order to avoid position shifts
	std::sort(insertions.begin(), insertions.end(),
		[](const Insertion& a, const Insertion& b){ return a.pos > b.pos; });

	for (const auto& ins : insertions)
		content.insert(ins.pos, ins.text);

	content += appendix;

	std::ofstream out(tomlPath, std::ios::trunc);
	if (!out) return;
	out << content;
	out.flush();

	g_pLog->info("Config: migrated %s — appended new entries\n", tomlPath.c_str());
}

static void onFileChange(const std::string& path, uint32_t mask)
{
	(void)path;
	(void)mask;
	g_config.loadSettings();
}

static void collectAppIdDelta(const std::unordered_set<uint32_t>& previous,
	const std::unordered_set<uint32_t>& current,
	std::vector<uint32_t>& additions,
	std::vector<uint32_t>& removals)
{
	for (uint32_t id : current)
	{
		if (!previous.contains(id)) additions.push_back(id);
	}

	for (uint32_t id : previous)
	{
		if (!current.contains(id)) removals.push_back(id);
	}
}

bool CConfig::init()
{
	migrateConfig(); // Try YAML→TOML conversion first (before createFile)
	// FileWatcher spawn is deferred to startWatcher() (called from load() in
	// main.cpp). Creating it here — during la_preinit — produces a watch
	// thread that doesn't survive Steam's main() init.
	createFile();
	loadSettings();
	return true;
}

void CConfig::startWatcher()
{
	if (watcher) return;
	watcher = new CFileWatcher(onFileChange);
	watcher->addFile(getPath().c_str());
	watcher->start();
}

CConfig::~CConfig()
{
	shutdown();
}

void CConfig::shutdown()
{
	if (watcher)
	{
		delete watcher;
		watcher = nullptr;
	}
}

bool CConfig::loadSettings()
{
	const bool queueLiveAppIdChanges = LuaLoader::initDone();
	const auto previousAddedAppIds = queueLiveAppIdChanges
		? addedAppIds.get()
		: std::unordered_set<uint32_t>();

	toml::table node;
	try
	{
		node = toml::parse_file(getPath());
	}
	catch (const toml::parse_error& pe)
	{
		g_pLog->notifyLong("Error parsing config.toml! %.*s\nUsing defaults",
			static_cast<int>(pe.description().size()), pe.description().data());
		node = toml::table{};
	}

	__parseError = false;
	
	disableFamilyLock = getSetting<bool>(node, "DisableFamilyShareLock", true);
	useWhiteList = getSetting<bool>(node, "UseWhitelist", false);
	automaticFilter = getSetting<bool>(node, "AutoFilterList", true);
	playNotOwnedGames = getSetting<bool>(node, "PlayNotOwnedGames", false);
	packageInjection = getSetting<bool>(node, "PackageInjection", true);
	onlinePatterns = getSetting<bool>(node, "OnlinePatterns", true);
	notifications = getSetting<bool>(node, "Notifications", true);
	notifyInit = getSetting<bool>(node, "NotifyInit", true);
	api = getSetting<bool>(node, "API", true);
	fakeEmail = getSetting<std::string>(node, "FakeEmail", "");
	fakeWalletBalance = getSetting<int32_t>(node, "FakeWalletBalance", 0);
	disableCloud = getSetting<bool>(node, "DisableCloud", true);
	blockTicketRequests = getSetting<bool>(node, "BlockTicketRequests", true);
	offlineAchievementsSchema = getSetting<bool>(node, "OfflineAchievementsSchema", false);
	extendedLogging = getSetting<bool>(node, "ExtendedLogging", false);
	logLevel = getSetting<unsigned int>(node, "LogLevel", 2);

	//TODO: Create smart logging function to log them automatically via getSetting
	g_pLog->info("DisableFamilyShareLock: %i\n", disableFamilyLock.get());
	g_pLog->info("UseWhitelist: %i\n", useWhiteList.get());
	g_pLog->info("AutoFilterList: %i\n", automaticFilter.get());
	g_pLog->info("PlayNotOwnedGames: %i\n", playNotOwnedGames.get());
	g_pLog->info("PackageInjection: %i\n", packageInjection.get());
	g_pLog->info("OnlinePatterns: %i\n", onlinePatterns.get());
	g_pLog->info("Notifications: %i\n", notifications.get());
	g_pLog->info("NotifyInit: %i\n", notifyInit.get());
	g_pLog->info("API: %i\n", api.get());
	g_pLog->info("FakeEmail: %s\n", fakeEmail.get().c_str());
	g_pLog->info("FakeWalletBalance: %i\n", fakeWalletBalance.get());
	g_pLog->info("DisableCloud: %i\n", disableCloud.get());
	g_pLog->info("BlockTicketRequests: %i\n", blockTicketRequests.get());
	g_pLog->info("OfflineAchievementsSchema: %i\n", offlineAchievementsSchema.get());
	g_pLog->info("ExtendedLogging: %i\n", extendedLogging.get());
	g_pLog->info("LogLevel: %i\n", logLevel.get());

	appIds = getList<uint32_t>(node, "AppIds");
	fakeOffline = getList<uint32_t>(node, "FakeOffline");

	// [FakeAppIds] hosts both a flat real→fake int map AND an optional
	// [[FakeAppIds.Flags]] array of tables. getMap<uint32_t,uint32_t> can't
	// handle the latter (non-integer key "Flags" trips stoul). Parse the
	// table by hand: integer keys → map, "Flags" array → rule vector,
	// anything else → __parseError.
	{
		std::unordered_map<uint32_t, uint32_t> map;
		std::vector<FakeAppIdFlagRule> rules;
		if (auto* tbl = node["FakeAppIds"].as_table()) {
			for (const auto& [k, v] : *tbl) {
				const std::string key(k.str());
				if (key == "Flags") {
					auto* arr = v.as_array();
					if (!arr) {
						g_pLog->warn("FakeAppIds.Flags is not an array of tables — ignored\n");
						__parseError = true;
						continue;
					}
					for (const auto& item : *arr) {
						auto* row = item.as_table();
						if (!row) {
							g_pLog->warn("FakeAppIds.Flags: entry is not a table — skipped\n");
							__parseError = true;
							continue;
						}
						FakeAppIdFlagRule rule;
						rule.flag = (*row)["Flag"].value_or(std::string(""));
						auto fakeOpt = (*row)["FakeAppId"].value<int64_t>();
						if (rule.flag.empty() || !fakeOpt || *fakeOpt <= 0
						 || *fakeOpt > std::numeric_limits<uint32_t>::max()) {
							g_pLog->warn("FakeAppIds.Flags: entry missing/invalid Flag or FakeAppId — skipped\n");
							__parseError = true;
							continue;
						}
						rule.fakeAppId = static_cast<uint32_t>(*fakeOpt);
						auto loadAppList = [&](const char* field, std::unordered_set<uint32_t>& dst) {
							if (auto* a = (*row)[field].as_array()) {
								for (const auto& e : *a) {
									auto val = e.value<int64_t>();
									if (!val || *val < 0
									 || *val > std::numeric_limits<uint32_t>::max()) {
										g_pLog->warn("FakeAppIds.Flags \"%s\": %s entry is not a valid uint32 — skipped\n",
											rule.flag.c_str(), field);
										__parseError = true;
										continue;
									}
									dst.emplace(static_cast<uint32_t>(*val));
								}
							}
						};
						loadAppList("Apps", rule.apps);
						loadAppList("ExcludeApps", rule.excludeApps);
						g_pLog->info("FakeAppIds.Flags: \"%s\" -> %u (apps=%zu exclude=%zu)\n",
							rule.flag.c_str(), rule.fakeAppId, rule.apps.size(), rule.excludeApps.size());
						rules.push_back(std::move(rule));
					}
				} else {
					// Use from_chars instead of stoul: with -O3 -flto an out_of_range
					// thrown by stoul (e.g. on `9999999999` from a 32-bit build)
					// escaped the surrounding catch and aborted Steam at init.
					// from_chars never throws — fail paths come back through ec.
					uint64_t parsed = 0;
					const char* begin = key.data();
					const char* end = key.data() + key.size();
					auto [ptr, ec] = std::from_chars(begin, end, parsed);
					if (ec != std::errc() || ptr != end
					 || parsed > std::numeric_limits<uint32_t>::max()) {
						g_pLog->warn("FakeAppIds: key \"%s\" is neither an AppId nor \"Flags\" — ignored\n", key.c_str());
						__parseError = true;
						continue;
					}
					const uint32_t intKey = static_cast<uint32_t>(parsed);
					// Reject non-int values (e.g. `2070270 = "abc"`) instead of
					// silently mapping to 0 — that silently breaks the user's
					// intended mapping with no signal that anything is wrong.
					auto valOpt = v.value<int64_t>();
					if (!valOpt || *valOpt < 0
					 || *valOpt > std::numeric_limits<uint32_t>::max()) {
						g_pLog->warn("FakeAppIds[%u]: value is not a valid uint32 — ignored\n", intKey);
						__parseError = true;
						continue;
					}
					map[intKey] = static_cast<uint32_t>(*valOpt);
				}
			}
		}
		fakeAppIds = std::move(map);
		fakeAppIdFlags = std::move(rules);
	}
	gameTitles = getMap<uint32_t, std::string>(node, "GameTitles");
	subscriptionTimestamps = getMap<uint32_t, uint32_t>(node, "SubscriptionTimestamps");

	// AdditionalApps + AppTokens carry a config-file baseline that reconcileIntoConfig()
	// unions the live lua tables onto. Parse them into locals and record the config
	// baseline first (supports lua hot-removal, not just union add).
	const auto cfgAdditional = getList<uint32_t>(node, "AdditionalApps");
	const auto cfgTokens     = getMap<uint32_t, uint64_t>(node, "AppTokens");
	yamlAddedAppIds = cfgAdditional;
	yamlAppTokens   = cfgTokens;

	// Atomic-replace guard for the FileWatcher hot-reload window: when reconcile runs
	// (queueLiveAppIdChanges) it performs the single locked addedAppIds/appTokens =
	// config ∪ lua write below, so the live sets transition old→new in one step and are
	// never transiently narrowed to the config-only subset. A narrowed set would briefly
	// drop lua addappid ids, flipping isControlledApp and thus per-app cloud/ownership
	// decisions mid-reload. On initial load (lua not up yet, reconcile gated off)
	// assign the config set directly.
	if (!queueLiveAppIdChanges)
	{
		addedAppIds = cfgAdditional;
		appTokens   = cfgTokens;
	}

	if (auto* idleNode = node["IdleStatus"].as_table())
	{
		try
		{
			auto appId = static_cast<uint32_t>((*idleNode)["AppId"].value_or(int64_t(0)));
			auto title = (*idleNode)["Title"].value_or(std::string(""));

			idleStatus = FakeGame_t { appId, title };

			g_pLog->info("Idle status %s with AppId %u\n", title.c_str(), appId);
		}
		catch(...)
		{
			__parseError = true;
		}
	}

	if (auto* dlcNode = node["DlcData"].as_table())
	{
		auto _dlcData = dlcData.empty();

		for (const auto& [appKey, appVal] : *dlcNode)
		{
			try
			{
				const uint32_t parentId = static_cast<uint32_t>(std::stoul(std::string(appKey.str())));

				CDlcData data;
				data.parentId = parentId;
				g_pLog->info("Adding DlcData for %u\n", parentId);

				auto* dlcs = appVal.as_table();
				if (!dlcs) continue;
				for (const auto& [dlcKey, dlcVal] : *dlcs)
				{
					const uint32_t dlcId = static_cast<uint32_t>(std::stoul(std::string(dlcKey.str())));
					const std::string dlcName = dlcVal.value_or(std::string(""));

					data.dlcIds[dlcId] = dlcName;
					g_pLog->info("DlcId %u -> %s\n", dlcId, dlcName.c_str());
				}

				_dlcData[parentId] = data;
			}
			catch(...)
			{
				__parseError = true;
				break;
			}
		}

		dlcData = _dlcData;
	}

	if (auto* denuvoNode = node["DenuvoGames"].as_table())
	{
		auto _denuvoGames = denuvoGames.empty();

		for (const auto& [steamKey, steamVal] : *denuvoNode)
		{
			try
			{
				const uint32_t steamId = static_cast<uint32_t>(std::stoul(std::string(steamKey.str())));
				_denuvoGames[steamId] = std::unordered_set<uint32_t>();

				auto* appArr = steamVal.as_array();
				if (!appArr) continue;
				for (const auto& appNode : *appArr)
				{
					auto v = appNode.value<int64_t>();
					if (v)
					{
						_denuvoGames[steamId].emplace(static_cast<uint32_t>(*v));

						//Not logging SteamId for privacy
						g_pLog->info("Added DenuvoGame %u\n", static_cast<uint32_t>(*v));
					}
				}
			}
			catch (...)
			{
				__parseError = true;
			}
		}

		denuvoGames.set(_denuvoGames);
	}
	// Manifest — optional nested section. Manifest.Providers selects the request-code provider
	// chain (array or scalar string), passed to ManifestProvider::setProviders() after load.
	// If absent/empty, restore the default chain (opensteamtool -> wudrm -> steamrun), which makes
	// config hot-reload behave the same as a fresh start.
	{
		std::vector<std::string> providerList;
		bool useLuaOverrides = true;
		uint32_t timeoutConnectMs = 5000;
		uint32_t timeoutTotalMs = 10000;
		bool reuseConnection = true;
		if (auto* mfst = node["Manifest"].as_table())
		{
			// Manifest.Providers — accepts either an array or a single string.
			if (auto* prov = (*mfst)["Providers"].as_array())
			{
				for (const auto& p : *prov)
					if (auto s = p.value<std::string>())
						providerList.push_back(*s);
			}
			else if (auto s = (*mfst)["Providers"].value<std::string>())
			{
				providerList.push_back(*s);
			}
			useLuaOverrides = (*mfst)["UseLuaManifestOverrides"].value_or(true);
			timeoutConnectMs = static_cast<uint32_t>((*mfst)["TimeoutConnectMs"].value_or(int64_t(5000)));
			timeoutTotalMs = static_cast<uint32_t>((*mfst)["TimeoutTotalMs"].value_or(int64_t(10000)));
			reuseConnection = (*mfst)["ReuseConnection"].value_or(true);
		}
		useLuaManifestOverrides = useLuaOverrides;
		manifestTimeoutConnectMs = timeoutConnectMs;
		manifestTimeoutTotalMs = timeoutTotalMs;
		manifestReuseConnection = reuseConnection;
		g_pLog->info("Manifest.UseLuaManifestOverrides: %i\n", useLuaManifestOverrides.get());
		g_pLog->info("Manifest.TimeoutsMs: connect=%u total=%u\n",
			manifestTimeoutConnectMs.get(), manifestTimeoutTotalMs.get());
		g_pLog->info("Manifest.ReuseConnection: %i\n", manifestReuseConnection.get());
		// Apply the configured chain; absent/empty Providers restores the default all-built-ins chain.
		if (providerList.empty())
			ManifestProvider::resetProviders();
		else
			ManifestProvider::setProviders(providerList);
		manifestProvider = ManifestProvider::activeProviderChainSummary();
	}

	// Lua.Paths — optional list of extra directories to scan for .lua plugin files.
	// Missing or empty section is silently ignored (it is optional).
	{
		std::vector<std::string> paths;
		if (auto* luaNode = node["Lua"].as_table())
			if (auto* arr = (*luaNode)["Paths"].as_array())
				for (const auto& entry : *arr)
					if (auto s = entry.value<std::string>())
						paths.push_back(*s);
		luaPaths = paths;
		if (!paths.empty())
		{
			g_pLog->info("Lua.Paths: %zu extra dir(s) configured\n", paths.size());
		}
	}

	// [ProtonInject] — Dir (optional string) + [[ProtonInject.Dlls]] array of tables.
	{
		ProtonInjectConfig cfg;
		if (auto* pi = node["ProtonInject"].as_table()) {
			cfg.dir = (*pi)["Dir"].value_or(std::string(""));
			if (auto* arr = (*pi)["Dlls"].as_array()) {
				for (const auto& item : *arr) {
					auto* tbl = item.as_table();
					if (!tbl) continue;
					ProtonInjectEntry entry;
					entry.path = (*tbl)["Path"].value_or(std::string(""));
					entry.flag = (*tbl)["Flag"].value_or(std::string(""));
					if (auto* apps = (*tbl)["Apps"].as_array()) {
						for (const auto& a : *apps) {
							if (auto v = a.value<int64_t>()) {
								if (*v >= 0 && *v <= std::numeric_limits<uint32_t>::max())
									entry.apps.emplace(static_cast<uint32_t>(*v));
								else
									__parseError = true;
							}
							else { __parseError = true; }
						}
					}
					if (!entry.path.empty() && (!entry.apps.empty() || !entry.flag.empty())) {
						if (!entry.flag.empty())
							g_pLog->info("ProtonInject: %s -> flag \"%s\" + %zu app(s)\n",
								entry.path.c_str(), entry.flag.c_str(), entry.apps.size());
						else
							g_pLog->info("ProtonInject: %s -> %zu app(s)\n",
								entry.path.c_str(), entry.apps.size());
						cfg.dlls.push_back(std::move(entry));
					}
				}
			}
		}
		protonInject = std::move(cfg);
	}

	if (__parseError)
		g_pLog->notify("Issues during config loading encountered! Parsing error(s)");
	__parseError = false;

	// Perform the single atomic addedAppIds/appTokens = config ∪ lua write. This matters
	// on FileWatcher hot-reload, where loadSettings() re-runs but LuaLoader::init()
	// does NOT — without this, lua-only appIds would vanish from g_config until a
	// restart. The config baseline was parsed into yamlAddedAppIds/yamlAppTokens above
	// but the live sets were intentionally NOT narrowed to it (see the atomic-replace
	// guard), so on hot-reload this update is the sole writer of the live sets.
	//
	// Gate on initDone(): before init() finishes its tables are empty (so this was
	// a no-op anyway) AND being written on the load thread, so a FileWatcher
	// hot-reload merging here would race that construction. After init() it is safe
	// (the tables are frozen, read-only).
	if (queueLiveAppIdChanges)
	{
		LuaLoader::reconcileIntoConfig();

		const auto currentAddedAppIds = addedAppIds.get();
		std::vector<uint32_t> additions;
		std::vector<uint32_t> removals;
		collectAppIdDelta(previousAddedAppIds, currentAddedAppIds, additions, removals);
		Package::queueAppIdChanges(additions, removals);
	}

	return true;
}

bool CConfig::isAddedAppId(uint32_t appId)
{
	return addedAppIds.contains(appId);
}

bool CConfig::shouldExcludeAppId(uint32_t appId)
{
	bool exclude = false;
	//Proper way would be with getAppType, but that seems broken so we need to do this instead
	constexpr uint32_t ONE_BILLION = 1E9; //Implicit cast from double to unsigned int, hopefully this does not break anything
	if (appId >= ONE_BILLION) //Higher and equal to 10^9 gets used by Steam Internally
	{
		exclude = true;
	}
	else
	{
		bool found = appIds.contains(appId);
		exclude = !isAddedAppId(appId) && ((useWhiteList.get() && !found) || (!useWhiteList.get() && found));
	}

	g_pLog->once("shouldExcludeAppId(%u) -> %i\n", appId, exclude);
	return exclude;
}

uint32_t CConfig::getDenuvoGameOwner(uint32_t appId)
{
	for(const auto& tpl : denuvoGames.get())
	{
		if (tpl.second.contains(appId))
		{
			//g_pLog->once("%u is DenuvoGame\n", appId);
			return tpl.first;
		}
	}

	return 0;
}

CConfig g_config = CConfig();
