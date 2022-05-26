#ifndef STRINGIFICATION_H
#define STRINGIFICATION_H

#include <ostream>
#include <tuple>
#include <utility>

namespace std {
template <typename T1, typename T2>
ostream &operator<<(ostream &os, const pair<T1, T2> &p) {
  return os << "{" << p.first << ", " << p.second << "}";
}

template <typename... Ts>
ostream &operator<<(ostream &os, const tuple<Ts...> &t) {
  os << "{";
  bool f = 1;
  apply([&](auto &&...args) { ((os << (f ? "" : ", ") << args, f = 0), ...); },
        t);
  return os << "}";
}

template <typename T, typename = decltype(*begin(declval<T>())),
          typename = enable_if_t<!is_same<T, basic_string<char>>::value>>
ostream &operator<<(ostream &os, const T &c) {
  os << "[";
  for (auto it = begin(c); it != end(c); ++it)
    os << (it == begin(c) ? "" : ", ") << *it;
  return os << "]";
}

template <typename T, size_t size,
          typename = enable_if_t<!is_same<T, char>::value>>
ostream &operator<<(ostream &os, const T (&arr)[size]) {
  os << "[";
  for (auto it = begin(arr); it != end(arr); ++it)
    os << (it == begin(arr) ? "" : ", ") << *it;
  return os << "]";
}
}  // namespace std

#endif
