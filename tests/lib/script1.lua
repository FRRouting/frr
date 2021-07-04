function foo(a, b)
  a = a + b
  return {
    a = a,
    b = b,
  }
end

function fact(n)
  function helper(m)
    if m == 0 then
      return 1
    else
      return m * helper(m - 1)
    end
  end
  return {
    n = helper(n)
  }
end

function bad_return1()
end

function bad_return2()
  return 1
end

function bad_return3()
  error("Something bad!")
end

