package com.sparta.memo.service;

import com.sparta.memo.dto.MemoRequestDto;
import com.sparta.memo.dto.MemoResponseDto;
import com.sparta.memo.entity.Memo;
import com.sparta.memo.repository.MemoRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service// 빈으로 등록
public class MemoService {

    private final MemoRepository memoRepository; // final은 무조건 생성자로 주입
    public MemoService(MemoRepository memoRepository) {
        this.memoRepository = memoRepository;
    }



    public MemoResponseDto createMemo(MemoRequestDto requestDto) {
        // RequestDto -> Entity
        Memo memo = new Memo(requestDto);

        // DB 저장
        Memo saveMemo = memoRepository.save(memo);

        // Entity -> ResponseDto
        MemoResponseDto memoResponseDto = new MemoResponseDto(saveMemo);

        return memoResponseDto;
    }

    public List<MemoResponseDto> getMemos() {
        // DB 조회
        return memoRepository.findAllByOrderByCreatedAtDesc().stream().map(MemoResponseDto::fromMemo).toList();// 메모를 리스트 타입으로 반환
    }

    public MemoResponseDto getOneMemo(Long id) {
        // DB 조회
        Memo memo = memoRepository.findMemoById(id);

        return MemoResponseDto.fromMemo(memo);
    }

    @Transactional // updateMemo는 따로 Transactional 되어있지 않아 해줘야함
    public Memo updateMemo(Long id, MemoRequestDto requestDto, String password) {
        Memo memo = isPasswordValid(id, password);

        memo.update(requestDto); // update는 memo 클래스에서 만든 것

        return memo;
    }

    public Long deleteMemo(Long id, String password) {

        memoRepository.delete(isPasswordValid(id, password));

        return id;
    }

    private Memo findMemo(Long id) { // 메모 찾기
        return memoRepository.findById(id).orElseThrow(() ->  // null 시 오류 메시지 출력
                new IllegalArgumentException("선택한 메모는 존재하지 않습니다.")
        );
    }

    private Memo isPasswordValid(Long id, String providedPassword) {
        Memo memo = findMemo(id);

        if (!memo.getPassword().equals(providedPassword)) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        return memo;
    }

}