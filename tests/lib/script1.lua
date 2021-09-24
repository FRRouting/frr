
-- Positive testing

function foo(a, b)
  a = a + 1
  b = b + 1
  return {
    a = a,
    b = b,
  }
end

function bar(a, b)
  a = a + 1
  b = b + 1
  c = 303
  return {
    b = b,
    c = c,
  }
end

function fact(n)
  -- outer function must return a table
  -- inner functions can be used to recurse or as helpers
  function helper(m)
    if m == 0 then
      return 1
    else
      return m * helper(m - 1)
    end
  end
  return {
    ans = helper(n)
  }
end

-- Negative testing

function bad_return1()
end

function bad_return2()
  return 123
end

function bad_return3()
  return {}
end

function bad_return4()
  error("Something bad!")
end

