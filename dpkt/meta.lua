--
return {
    __call = function (self, buf)
        if self.init then
            return self:init(buf)
        end
    end,

    __gc = function (self)
        if self.del then
            self:del()
        end
    end
}
